/*-------------------------------------------------------------------------
 *
 * pg_shared_plans.c: Implementation of plan cache in shared memory.
 *
 * This program is open source, licensed under the PostgreSQL license.
 * For license terms, see the LICENSE file.
 *
 * Copyright (C) 2021: Julien Rouhaud
 *
 *-------------------------------------------------------------------------
 */


#include "postgres.h"
#include "fmgr.h"

#include "common/hashfn.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "optimizer/planner.h"
#include "pgstat.h"
#include "postmaster/bgworker.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/lwlock.h"
#include "storage/proc.h"
#include "storage/shmem.h"
#include "storage/shm_toc.h"
#include "tcop/cmdtag.h"
#include "utils/elog.h"
#include "utils/guc.h"
#include "utils/memutils.h"

PG_MODULE_MAGIC;

#define PGSP_MAGIC				0x20210318
#define PGSP_DATA_KEY			UINT64CONST(1)

#define PGSP_LEVEL				DEBUG1

typedef struct pgspHashKey
{
	Oid			dbid;			/* database OID */
	uint64		queryid;		/* query identifier */
} pgspHashKey;

typedef struct pgspEntry
{
	pgspHashKey key;			/* hash key of entry - MUST BE FIRST */
	slock_t		mutex;			/* protects the plan */
	dsa_pointer plan;
} pgspEntry;

/*
 * Global shared state
 */
typedef struct pgspSharedState
{
	bool		init_done;
	LWLock	   *lock;
	dsm_handle h;
} pgspSharedState;

/*---- Local variables ----*/

/* Saved hook values in case of unload */
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;
static planner_hook_type prev_planner_hook = NULL;

/* Links to shared memory state */
static pgspSharedState *pgsp = NULL;
static HTAB *pgsp_hash = NULL;

static bool pgsp_attached = false;

static dsm_segment *seg = NULL;
static shm_toc *toc = NULL;
static void *dsa_space = NULL;
static dsa_area *dsa = NULL;

/*---- GUC variables ----*/

static bool pgsp_enabled = true;
static int	pgsp_max = 1000;

/*---- Function declarations ----*/

PGDLLEXPORT void _PG_init(void);
PGDLLEXPORT void _PG_fini(void);

PG_FUNCTION_INFO_V1(pg_shared_plans_reset);

#if (PG_VERSION_NUM >= 90500)
void pgsp_main(Datum main_arg) pg_attribute_noreturn();
#else
void pgsp_main(Datum main_arg) __attribute__((noreturn));
#endif

static void pgsp_shmem_startup(void);
static PlannedStmt *pgsp_planner_hook(Query *parse,
									  const char *query_string,
									  int cursorOptions,
									  ParamListInfo boundParams);

static void pgsp_detach(dsm_segment *segment, Datum datum);
static void pgsp_init_dsm(void);
static Size pgsp_memsize(void);
static pgspEntry *pgsp_entry_alloc(pgspHashKey *key);


/*
 * Module load callback
 */
void
_PG_init(void)
{
	BackgroundWorker worker;

	elog(PGSP_LEVEL, "pg_init");

	if (!process_shared_preload_libraries_in_progress)
	{
		elog(ERROR, "This module can only be loaded via shared_preload_libraries");
		return;
	}

	/*
	 * Define (or redefine) custom GUC variables.
	 */
	DefineCustomBoolVariable("pg_shared_plans.enabled",
							 "Enable or disable pg_shared_plans.",
							 NULL,
							 &pgsp_enabled,
							 true,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

	DefineCustomIntVariable("pg_shared_plans.max",
							"Sets the maximum number of plans tracked by pg_shared_plans.",
							NULL,
							&pgsp_max,
							1000,
							100,
							INT_MAX,
							PGC_POSTMASTER,
							0,
							NULL,
							NULL,
							NULL);

	EmitWarningsOnPlaceholders("pg_shared_plans");

	/*
	 * Request additional shared resources.  (These are no-ops if we're not in
	 * the postmaster process.)  We'll allocate or attach to the shared
	 * resources in pgsp_shmem_startup().
	 */
	RequestAddinShmemSpace(pgsp_memsize());
	RequestNamedLWLockTranche("pg_shared_plans", 1);

	/* Install hooks */
	prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = pgsp_shmem_startup;
	prev_planner_hook = planner_hook;
	planner_hook = pgsp_planner_hook;

	/*
	 * Register the worker processes.
	 * XXX didn't find another way to keep the mapping forever.
	 */
	memset(&worker, 0, sizeof(worker));
	worker.bgw_flags =
		BGWORKER_SHMEM_ACCESS;
	worker.bgw_start_time = BgWorkerStart_ConsistentState;
#if (PG_VERSION_NUM >= 100000)
	snprintf(worker.bgw_library_name, BGW_MAXLEN, "pg_shared_plans");
	snprintf(worker.bgw_function_name, BGW_MAXLEN, "pgsp_main");
#else
	worker.bgw_main = pgsp_main;
#endif
	snprintf(worker.bgw_name, BGW_MAXLEN, "pg_shared_plans");
	worker.bgw_restart_time = 10;
	worker.bgw_main_arg = (Datum) 0;
#if (PG_VERSION_NUM >= 90400)
	worker.bgw_notify_pid = 0;
#endif
	RegisterBackgroundWorker(&worker);
}

void
_PG_fini(void)
{
	/* uninstall hooks */
	shmem_startup_hook = prev_shmem_startup_hook;
	planner_hook = prev_planner_hook;

}

void
pgsp_main(Datum main_arg)
{
	MemoryContext old_context;
	shm_toc_estimator estimator;
	size_t size;

	Assert(!pgsp->init_done);

	BackgroundWorkerUnblockSignals();

	LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);

	/* First time, alloc everything */
	shm_toc_initialize_estimator(&estimator);
	shm_toc_estimate_keys(&estimator, 1);
	shm_toc_estimate_chunk(&estimator, pgsp_max * MAXALIGN(sizeof(pgspEntry)));
	/* Let's plan for 100kB per plan */
	shm_toc_estimate_chunk(&estimator, pgsp_max * 100 * 1024);

	size = shm_toc_estimate(&estimator);
	seg = dsm_create(size, DSM_CREATE_NULL_IF_MAXSEGMENTS);

	if (seg == NULL)
	{
		elog(PGSP_LEVEL, "Too bad");
		pgsp->init_done = true;
		exit(0);
	}

	pgsp->h = dsm_segment_handle(seg);

	old_context = MemoryContextSwitchTo(TopMemoryContext);
	toc = shm_toc_create(PGSP_MAGIC,
						 dsm_segment_address(seg),
						 size);

	size -= 1024;

	dsa_space = shm_toc_allocate(toc, size);
	dsa = dsa_create_in_place(dsa_space,
			size,
			LWTRANCHE_PER_SESSION_DSA,
			seg);
	shm_toc_insert(toc, PGSP_DATA_KEY, dsa_space);

	dsm_pin_segment(seg);
	dsa_pin_mapping(dsa);

	MemoryContextSwitchTo(old_context);

	on_dsm_detach(seg, pgsp_detach, (Datum) 0);

	pgsp->init_done = true;
	LWLockRelease(pgsp->lock);

	/* And now sleep forever */
	for (;;)
	{
		/* sleep */
		WaitLatch(&MyProc->procLatch,
				  WL_LATCH_SET | WL_POSTMASTER_DEATH,
				  0
#if PG_VERSION_NUM >= 100000
				  ,PG_WAIT_EXTENSION
#endif
				  );
		ResetLatch(&MyProc->procLatch);
	}
}
/*
 * shmem_startup hook: allocate or attach to shared memory,
 */
static void
pgsp_shmem_startup(void)
{
	bool				found;
	HASHCTL		info;

	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

	/* reset in case this is a restart within the postmaster */
	pgsp = NULL;
	pgsp_hash = NULL;

	/*
	 * Create or attach to the shared memory state, including hash table
	 */
	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);

	pgsp = ShmemInitStruct("pg_shared_plans",
						   sizeof(pgspSharedState),
						   &found);

	if (!found)
	{
		/* First time through ... */
		memset(pgsp, 0, sizeof(pgspSharedState));
		pgsp->lock = &(GetNamedLWLockTranche("pg_shared_plans"))->lock;
	}

	info.keysize = sizeof(pgspHashKey);
	info.entrysize = sizeof(pgspEntry);
	pgsp_hash = ShmemInitHash("pg_shared_plans hash",
							  pgsp_max, pgsp_max,
							  &info,
							  HASH_ELEM | HASH_BLOBS);

	LWLockRelease(AddinShmemInitLock);
}

static PlannedStmt *
pgsp_planner_hook(Query *parse,
				  const char *query_string,
				  int cursorOptions,
				  ParamListInfo boundParams)
{
	Query		   *generic_parse;
	PlannedStmt	   *result, *generic;
	pgspHashKey		key;
	pgspEntry	   *entry;

	if (!pgsp_enabled)
		goto fallback;

	elog(PGSP_LEVEL, "plan");

	if (parse->queryId == UINT64CONST(0))
	{
		elog(PGSP_LEVEL, "no queryid!");
		goto fallback;
	}

	if (boundParams == NULL)
	{
		elog(PGSP_LEVEL, "no params!");
		//goto fallback;
	}

	pgsp_init_dsm();

	key.dbid = MyDatabaseId;
	key.queryid = parse->queryId;

	elog(PGSP_LEVEL, "looking for %d/%lu", key.dbid, key.queryid);

	/* Lookup the hash table entry with shared lock. */
	LWLockAcquire(pgsp->lock, LW_SHARED);
	entry = (pgspEntry *) hash_search(pgsp_hash, &key, HASH_FIND, NULL);
	LWLockRelease(pgsp->lock);

	/* Create new entry, if not present */
	if (!entry)
	{
		/* Need exclusive lock to make a new hashtable entry - promote */
		LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);

		/* OK to create a new hashtable entry */
		entry = pgsp_entry_alloc(&key);

		LWLockRelease(pgsp->lock);
	}

	if (entry == NULL)
	{
		/* pgsp_entry_alloc complained about dealloc already */
		goto fallback;
	}

	if (entry->plan != 0)
	{
		char *local = dsa_get_address(dsa, entry->plan);

		elog(NOTICE, "found entry, bypassing planner");

		result = (PlannedStmt *) stringToNode(local);

		return result;
	}
	else
		elog(PGSP_LEVEL, "entry not found :(");

	generic_parse = copyObject(parse);

	if (prev_planner_hook)
		result = (*prev_planner_hook) (parse, query_string, cursorOptions, boundParams);
	else
		result = standard_planner(parse, query_string, cursorOptions, boundParams);

	generic = standard_planner(generic_parse, query_string, cursorOptions, NULL);

	Assert(entry);

	if (entry->plan == 0)
	{
		volatile pgspEntry *e = (volatile pgspEntry *) entry;
		char *local;
		char *serialized;
		size_t len;

		serialized = nodeToString(generic);

		len = strlen(serialized) + 1;

		/*
		 * Grab the spinlock while updating the plan
		 */
		SpinLockAcquire(&e->mutex);

		if (e->plan == 0)
		{
			e->plan = dsa_allocate(dsa, len);

			local = (char *) dsa_get_address(dsa, e->plan);
			/*
			local->commandType = result->commandType;
			local->queryId = result->queryId;
			*/
			memcpy(local, serialized, len);
		}
		SpinLockRelease(&e->mutex);
	}

	return result;

fallback:
	if (prev_planner_hook)
		return (*prev_planner_hook) (parse, query_string, cursorOptions, boundParams);
	else
		return standard_planner(parse, query_string, cursorOptions, boundParams);
}

static void
pgsp_detach(dsm_segment *segment, Datum datum)
{
	elog(WARNING, "pgsp_detach");
}

/* see GetSessionDsmHandle */
static void
pgsp_init_dsm(void)
{
	MemoryContext old_context;
	bool init_done;

	LWLockAcquire(pgsp->lock, LW_SHARED);
	init_done = pgsp->init_done;
	LWLockRelease(pgsp->lock);

	/* already did the job */
	if (pgsp_attached)
		return;

	/* bgworker didn't allocated the dsm yet, try next time. */
	if (!init_done)
		return;

	/* We couldn't get the shm in the first place */
	if (pgsp->h == 0)
	{
		elog(PGSP_LEVEL, "no h");
		return;
	}

	old_context = MemoryContextSwitchTo(TopMemoryContext);
	seg = dsm_attach(pgsp->h);
	if (seg == 0)
	{
		elog(PGSP_LEVEL, "could not attach");
		return;
	}

	dsm_pin_mapping(seg);

	toc = shm_toc_attach(PGSP_MAGIC, dsm_segment_address(seg));
	dsa_space = shm_toc_lookup(toc, PGSP_DATA_KEY, seg);
	dsa = dsa_attach_in_place(dsa_space, seg);

	dsa_pin_mapping(dsa);

	pgsp_attached = true;

	MemoryContextSwitchTo(old_context);
}

/*
 * Estimate shared memory space needed.
 */
static Size
pgsp_memsize(void)
{
	Size		size;

	size = CACHELINEALIGN(sizeof(pgspSharedState));
	size = add_size(size, hash_estimate_size(pgsp_max, sizeof(pgspEntry)));

	return size;
}

/*
 * Allocate a new hashtable entry.
 * caller must hold an exclusive lock on pgsp->lock
 */
static pgspEntry *
pgsp_entry_alloc(pgspHashKey *key)
{
	pgspEntry  *entry;
	bool		found;

	/* FIXME Need to write eviction code */
	if (hash_get_num_entries(pgsp_hash) >= pgsp_max)
	{
		elog(WARNING, "FIXME");
		return NULL;
	}

	/* Make space if needed */
	//while (hash_get_num_entries(pgsp_hash) >= pgsp_max)
	//	entry_dealloc();

	/* Find or create an entry with desired hash code */
	entry = (pgspEntry *) hash_search(pgsp_hash, key, HASH_ENTER, &found);

	if (!found)
	{
		/* New entry, initialize it */
		entry->plan = 0;
		/* re-initialize the mutex each time ... we assume no one using it */
		SpinLockInit(&entry->mutex);
	}

	return entry;
}

Datum
pg_shared_plans_reset(PG_FUNCTION_ARGS)
{
	PG_RETURN_VOID();
}
