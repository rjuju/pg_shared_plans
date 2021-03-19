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
	dsm_handle  h;
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

//static bool pgsp_attached = false;

//static dsm_segment *seg = NULL;
//static shm_toc *toc = NULL;
//static void *dsa_space = NULL;
//static dsa_area *dsa = NULL;

/*---- GUC variables ----*/

static bool pgsp_enabled = true;
static int	pgsp_max = 1000;

/*---- Function declarations ----*/

PGDLLEXPORT void _PG_init(void);
PGDLLEXPORT void _PG_fini(void);

PG_FUNCTION_INFO_V1(pg_shared_plans_reset);

//#if (PG_VERSION_NUM >= 90500)
//void pgsp_main(Datum main_arg) pg_attribute_noreturn();
//#else
//void pgsp_main(Datum main_arg) __attribute__((noreturn));
//#endif

static void pgsp_shmem_startup(void);
static PlannedStmt *pgsp_planner_hook(Query *parse,
									  const char *query_string,
									  int cursorOptions,
									  ParamListInfo boundParams);

static void pgsp_detach(dsm_segment *segment, Datum datum);
static uint32 pgsp_hash_fn(const void *key, Size keysize);
static int pgsp_match_fn(const void *key1, const void *key2, Size keysize);
static Size pgsp_memsize(void);
static pgspEntry *pgsp_entry_alloc(pgspHashKey *key);


/*
 * Module load callback
 */
void
_PG_init(void)
{
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
							200,
							100,
							/*
							 * FIXME: should allocate multiple plans per
							 * segment, as there can only be
							 * PG_DYNSHMEM_FIXED_SLOTS +
							 *   PG_DYNSHMEM_SLOTS_PER_BACKEND * MaxBackends
							 * segments.  Leave some room for the rest of
							 * infrastructure using dsm segments.
							 */
							5 * MaxConnections,
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
}

void
_PG_fini(void)
{
	/* uninstall hooks */
	shmem_startup_hook = prev_shmem_startup_hook;
	planner_hook = prev_planner_hook;

}

//void
//pgsp_main(Datum main_arg)
//{
//	MemoryContext old_context;
//	shm_toc_estimator estimator;
//	size_t size;
//
//	Assert(!pgsp->init_done);
//
//	BackgroundWorkerUnblockSignals();
//
//	LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);
//
//	/* First time, alloc everything */
//	shm_toc_initialize_estimator(&estimator);
//	shm_toc_estimate_keys(&estimator, 1);
//	shm_toc_estimate_chunk(&estimator, pgsp_max * MAXALIGN(sizeof(pgspEntry)));
//	/* Let's plan for 100kB per plan */
//	shm_toc_estimate_chunk(&estimator, pgsp_max * 100 * 1024);
//
//	size = shm_toc_estimate(&estimator);
//	seg = dsm_create(size, DSM_CREATE_NULL_IF_MAXSEGMENTS);
//
//	if (seg == NULL)
//	{
//		elog(PGSP_LEVEL, "Too bad");
//		pgsp->init_done = true;
//		LWLockRelease(pgsp->lock);
//		exit(0);
//	}
//
//	dsm_pin_segment(seg);
//
//	pgsp->h = dsm_segment_handle(seg);
//
//	old_context = MemoryContextSwitchTo(TopMemoryContext);
//	toc = shm_toc_create(PGSP_MAGIC,
//						 dsm_segment_address(seg),
//						 size);
//
//	size -= 1024;
//
//	dsa_space = shm_toc_allocate(toc, size);
//	dsa = dsa_create_in_place(dsa_space,
//			size,
//			LWTRANCHE_PER_SESSION_DSA,
//			seg);
//	shm_toc_insert(toc, PGSP_DATA_KEY, dsa_space);
//
//	dsm_pin_segment(seg);
//	dsa_pin_mapping(dsa);
//
//	MemoryContextSwitchTo(old_context);
//
//	on_dsm_detach(seg, pgsp_detach, (Datum) 0);
//
//	pgsp->init_done = true;
//	LWLockRelease(pgsp->lock);
//
//	/* And now sleep forever */
//	for (;;)
//	{
//		/* sleep */
//		WaitLatch(&MyProc->procLatch,
//				  WL_LATCH_SET | WL_POSTMASTER_DEATH,
//				  0
//#if PG_VERSION_NUM >= 100000
//				  ,PG_WAIT_EXTENSION
//#endif
//				  );
//		ResetLatch(&MyProc->procLatch);
//	}
//}
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
	info.hash = pgsp_hash_fn;
	info.match = pgsp_match_fn;
	pgsp_hash = ShmemInitHash("pg_shared_plans hash",
							  pgsp_max, pgsp_max,
							  &info,
							  HASH_ELEM | HASH_FUNCTION | HASH_COMPARE);

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
	dsm_handle h = 0;

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

	key.dbid = MyDatabaseId;
	key.queryid = parse->queryId;

	elog(PGSP_LEVEL, "looking for %d/%lu", key.dbid, key.queryid);

	/* Lookup the hash table entry with shared lock. */
	LWLockAcquire(pgsp->lock, LW_SHARED);
	entry = (pgspEntry *) hash_search(pgsp_hash, &key, HASH_FIND, NULL);

	if (entry != NULL)
	{
		volatile pgspEntry *e = (volatile pgspEntry *) entry;

		/*
		 * Grab the spinlock to get the handle
		 */
		SpinLockAcquire(&e->mutex);
		h = entry->h;
		SpinLockRelease(&e->mutex);
	}

	if (h != DSM_HANDLE_INVALID)
	{
		dsm_segment *eseg;
		shm_toc *etoc;
		char *local;

		eseg = dsm_attach(h);
		if (eseg == NULL)
		{
			LWLockRelease(pgsp->lock);
			goto fallback;
		}

		etoc = shm_toc_attach(PGSP_MAGIC, dsm_segment_address(eseg));

		local = (char *) shm_toc_lookup(etoc, 0, true);

		if (local != NULL)
		{
			elog(NOTICE, "found entry, bypassing planner");

			result = (PlannedStmt *) stringToNode(local);
			dsm_detach(eseg);

			goto release;
		}

		dsm_detach(eseg);
	}
	else
		elog(PGSP_LEVEL, "entry not found :(");

	LWLockRelease(pgsp->lock);

	generic_parse = copyObject(parse);

	if (prev_planner_hook)
		result = (*prev_planner_hook) (parse, query_string, cursorOptions, boundParams);
	else
		result = standard_planner(parse, query_string, cursorOptions, boundParams);

	generic = standard_planner(generic_parse, query_string, cursorOptions, NULL);

	/* Save the plan if no one did it yet */
	if (!entry)
	{
		volatile pgspEntry *e;
		dsm_segment *eseg = NULL;
		char *serialized;
		size_t len, size;
		shm_toc_estimator estimator;

		serialized = nodeToString(generic);
		len = strlen(serialized) + 1;

		LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);
		entry = pgsp_entry_alloc(&key);

		/*
		 * out of memory
		 */
		if (entry == NULL)
		{
			elog(PGSP_LEVEL, "could not alloc entry");
			goto release;
		}

		e = (volatile pgspEntry *) entry;

		shm_toc_initialize_estimator(&estimator);
		shm_toc_estimate_keys(&estimator, 1);
		shm_toc_estimate_chunk(&estimator, len);
		shm_toc_estimate_chunk(&estimator, 200);
		size = shm_toc_estimate(&estimator);

		if (e->h == DSM_HANDLE_INVALID)
		{
			shm_toc *etoc;
			char *local;

			eseg = dsm_create(add_size(size, 2000), DSM_CREATE_NULL_IF_MAXSEGMENTS);
	
			/* out of memory */
			if (eseg == NULL)
			{
				elog(PGSP_LEVEL, "out of mem");
				goto release;
			}

			dsm_pin_segment(eseg);
			on_dsm_detach(eseg, pgsp_detach, (Datum) 0);

			e->h = dsm_segment_handle(eseg);
			etoc = shm_toc_create(PGSP_MAGIC, dsm_segment_address(eseg), size);
			size -= 200;
			local = (char *) shm_toc_allocate(etoc, size);
			memcpy(local, serialized, len);
			shm_toc_insert(etoc, 0, local);
			dsm_detach(eseg);
		}
		goto release;
	}

	goto finish;

release:
	Assert(LWLockHeldByMe(pgsp->lock));
	LWLockRelease(pgsp->lock);
finish:
	Assert(!LWLockHeldByMe(pgsp->lock));
	return result;

fallback:
	Assert(!LWLockHeldByMe(pgsp->lock));
	if (prev_planner_hook)
		return (*prev_planner_hook) (parse, query_string, cursorOptions, boundParams);
	else
		return standard_planner(parse, query_string, cursorOptions, boundParams);
}

static void
pgsp_detach(dsm_segment *segment, Datum datum)
{
	elog(PGSP_LEVEL, "pgsp_detach");
}

/* Calculate a hash value for a given key. */
static uint32
pgsp_hash_fn(const void *key, Size keysize)
{
	const pgspHashKey *k = (const pgspHashKey *) key;
	uint32 h;

	h = hash_combine(0, k->dbid);
	h = hash_combine(h, k->queryid);

	return h;
}

/* Compares two keys.  Zero means match. */
static int
pgsp_match_fn(const void *key1, const void *key2, Size keysize)
{
	const pgspHashKey *k1 = (const pgspHashKey *) key1;
	const pgspHashKey *k2 = (const pgspHashKey *) key2;

	if (k1->dbid == k2->dbid && k1->queryid == k2->queryid)
		return 0;
	else
		return 1;
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

	Assert(LWLockHeldByMeInMode(pgsp->lock, LW_EXCLUSIVE));

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
		entry->h = 0;
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
