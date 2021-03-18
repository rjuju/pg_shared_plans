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
#include "lib/dshash.h"
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
#define PGSP_HTAB_KEY			UINT64CONST(1)

#define PGSP_LEVEL				DEBUG1

typedef struct pgspHashKey
{
	Oid			dbid;			/* database OID */
	uint64		queryid;		/* query identifier */
} pgspHashKey;

typedef struct pgspEntry
{
	pgspHashKey key;			/* hash key of entry - MUST BE FIRST */
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
	dshash_table_handle htab_handle;
} pgspSharedState;

/*---- Local variables ----*/

/* Saved hook values in case of unload */
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;
static planner_hook_type prev_planner_hook = NULL;

/* Links to shared memory state */
static pgspSharedState *pgsp = NULL;

static dsm_segment *seg = NULL;
static shm_toc *toc = NULL;
static void *dsa_space = NULL;
static dsa_area *dsa = NULL;
static dshash_table *htab = NULL;

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
static int pgsp_shared_table_compare(const void *a, const void *b, size_t size,
							void *arg);
static uint32 pgsp_shared_table_hash(const void *a, size_t size, void *arg);

/* Parameters for the dshash table */
static const dshash_parameters pgsp_table_params = {
	sizeof(pgspHashKey),
	sizeof(pgspEntry),
	pgsp_shared_table_compare,
	pgsp_shared_table_hash,
	LWTRANCHE_PER_SESSION_DSA
};


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
							PGC_SIGHUP,
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
	RequestAddinShmemSpace(CACHELINEALIGN(sizeof(pgspSharedState)));
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
	shm_toc_insert(toc, PGSP_HTAB_KEY, dsa_space);

	dsm_pin_segment(seg);
	dsa_pin_mapping(dsa);

	/* Create the hash table of plans indexed by themselves. */
	htab = dshash_create(dsa, &pgsp_table_params, dsa);
	pgsp->htab_handle = dshash_get_hash_table_handle(htab);

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

	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

	/* reset in case this is a restart within the postmaster */
	pgsp = NULL;

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
	bool			found;

	if (!pgsp_enabled)
		return standard_planner(parse, query_string, cursorOptions,
				boundParams);

	elog(PGSP_LEVEL, "plan");

	if (parse->queryId == UINT64CONST(0))
	{
		elog(PGSP_LEVEL, "no queryid!");
		return standard_planner(parse, query_string, cursorOptions,
				boundParams);
	}

	if (boundParams == NULL)
	{
		elog(PGSP_LEVEL, "no params!");
		return standard_planner(parse, query_string, cursorOptions,
				boundParams);
	}

	pgsp_init_dsm();

	if (pgsp->htab_handle == 0)
	{
		elog(PGSP_LEVEL, "no htab_handle!");
		return standard_planner(parse, query_string, cursorOptions,
				boundParams);
	}

	if (htab == NULL)
	{
		elog(PGSP_LEVEL, "no htab!");
		return standard_planner(parse, query_string, cursorOptions,
				boundParams);
	}

	key.dbid = MyDatabaseId;
	key.queryid = parse->queryId;

	elog(PGSP_LEVEL, "looking for %d/%lu", key.dbid, key.queryid);
	entry = dshash_find(htab, &key, false);

	if (entry)
	{
		char *local = dsa_get_address(dsa, entry->plan);

		elog(NOTICE, "found entry, bypassing planner");

		result = (PlannedStmt *) stringToNode(local);

		dshash_release_lock(htab, entry);

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

	if (entry == NULL)
	{
		entry = dshash_find_or_insert(htab,
				&key,
				&found);

		if (!found)
		{
			char *local;
			char *serialized;
			size_t len;

			serialized = nodeToString(generic);

			len = strlen(serialized) + 1;

			entry->plan = dsa_allocate(dsa, len);

			local = (char *) dsa_get_address(dsa, entry->plan);
			/*
			local->commandType = result->commandType;
			local->queryId = result->queryId;
			*/
			memcpy(local, serialized, len);
		}

		dshash_release_lock(htab, entry);
	}

	return result;
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

	/* Already alloced or attached */
	if (htab != NULL)
		return;

	LWLockAcquire(pgsp->lock, LW_SHARED);
	init_done = pgsp->init_done;
	LWLockRelease(pgsp->lock);

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
	dsa_space = shm_toc_lookup(toc, PGSP_HTAB_KEY, seg);
	dsa = dsa_attach_in_place(dsa_space, seg);

	dsa_pin_mapping(dsa);

	htab = dshash_attach(dsa,
			&pgsp_table_params,
			pgsp->htab_handle,
			dsa);
	MemoryContextSwitchTo(old_context);
}

static int
pgsp_shared_table_compare(const void *a, const void *b, size_t size,
							void *arg)
{
	pgspHashKey *k1 = (pgspHashKey *) a;
	pgspHashKey *k2 = (pgspHashKey *) b;

	if (k1->dbid == k2->dbid && k1->queryid == k2->queryid)
		return 0;
	else
		return 1;
}

static uint32
pgsp_shared_table_hash(const void *a, size_t size, void *arg)
{
	pgspHashKey *k = (pgspHashKey *) a;
	uint32		h;

	h = hash_combine(0, k->dbid);
	h = hash_combine(h, k->queryid);

	return h;
}

Datum
pg_shared_plans_reset(PG_FUNCTION_ARGS)
{
	PG_RETURN_VOID();
}
