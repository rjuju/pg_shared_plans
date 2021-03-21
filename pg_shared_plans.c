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

#include "access/relation.h"
#include "commands/explain.h"
#include "common/hashfn.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "optimizer/planner.h"
#include "pgstat.h"
#include "storage/ipc.h"
#include "storage/latch.h"
#include "storage/lmgr.h"
#include "storage/lwlock.h"
#include "storage/proc.h"
#include "storage/shmem.h"
#include "storage/shm_toc.h"
#include "tcop/cmdtag.h"
#include "tcop/utility.h"
#include "utils/builtins.h"
#include "utils/elog.h"
#include "utils/guc.h"
#include "utils/memutils.h"

#include "pgsp_import.h"

PG_MODULE_MAGIC;

#define PGSP_MAGIC				0x20210318
#define PGSP_PLAN_KEY			UINT64CONST(1)
#define PGSP_REL_KEY			UINT64CONST(2)
#define PGSP_USAGE_INIT			(1.0)
#define ASSUMED_MEDIAN_INIT		(10.0)	/* initial assumed median usage */
#define USAGE_DECREASE_FACTOR	(0.99)	/* decreased every entry_dealloc */
#define USAGE_DEALLOC_PERCENT	5		/* free this % of entries at once */

typedef struct pgspHashKey
{
	Oid			userid;		/* user OID is plans has RLS */
	Oid			dbid;		/* database OID */
	uint64		queryid;	/* query identifier */
	uint32		constid;	/* hash of the consts still present */
} pgspHashKey;

typedef struct pgspEntry
{
	pgspHashKey key;		/* hash key of entry - MUST BE FIRST */
	dsm_handle  h;			/* only modified holding exclusive pgsp->lock */
	size_t		len;		/* serialized plan length */
	double		plantime;	/* first generic planning time */
	Cost		generic_cost; /* total cost of the stored plan */
	int			num_const;	/* # of const values in the plan */
	int			num_rels;	/* # of referenced base relations */
	slock_t		mutex;		/* protects following fields only */
	int64		bypass;		/* number of times magic happened */
	double		usage;		/* usage factor */
	Cost		total_custom_cost; /* total cost of custom plans planned */
	int64		num_custom_plans; /* # of custom plans planned */
} pgspEntry;

typedef struct pgspWalkerContext
{
	uint32	constid;
	int		num_const;
} pgspWalkerContext;

/*
 * Global shared state
 */
typedef struct pgspSharedState
{
	LWLock	   *lock;			/* protects hashtable search/modification */
	double		cur_median_usage;	/* current median usage in hashtable */
	slock_t		mutex;				/* protects following fields only */
	int64		dealloc;			/* # of times entries were deallocated */
	TimestampTz stats_reset;		/* timestamp with all stats reset */
} pgspSharedState;

/*---- Local variables ----*/

/* Saved hook values in case of unload */
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;
static planner_hook_type prev_planner_hook = NULL;

/* Links to shared memory state */
static pgspSharedState *pgsp = NULL;
static HTAB *pgsp_hash = NULL;

/*---- GUC variables ----*/

static bool pgsp_enabled;
static int	pgsp_max;
static int	pgsp_min_plantime;
static int	pgsp_threshold;
static bool pgsp_es_costs;
static int	pgsp_es_format;
static bool pgsp_es_verbose;

static const struct config_enum_entry pgsp_explain_format_options[] =
{
	{"text", EXPLAIN_FORMAT_TEXT, false},
	{"json", EXPLAIN_FORMAT_JSON, false},
	{"xml", EXPLAIN_FORMAT_XML, false},
	{"yaml", EXPLAIN_FORMAT_YAML, false},
	{NULL, 0, false},
};

/*---- Function declarations ----*/

PGDLLEXPORT void _PG_init(void);
PGDLLEXPORT void _PG_fini(void);

PG_FUNCTION_INFO_V1(pg_shared_plans_reset);
PG_FUNCTION_INFO_V1(pg_shared_plans_info);
PG_FUNCTION_INFO_V1(pg_shared_plans);

static void pgsp_shmem_startup(void);
static PlannedStmt *pgsp_planner_hook(Query *parse,
									  const char *query_string,
									  int cursorOptions,
									  ParamListInfo boundParams);

static void pgsp_detach(dsm_segment *segment, Datum datum);
static void pg_shared_plans_shutdown(Datum arg);

static void pgsp_accum_custom_plan(pgspHashKey *key, Cost cost);
static void pgsp_acquire_executor_locks(PlannedStmt *plannedstmt, bool acquire);
static dsm_segment *pgsp_allocate_plan(PlannedStmt *stmt, size_t *len,
									   int *num_rels);
static bool pgsp_choose_cache_plan(pgspEntry *entry, bool *accum_custom_stats);
static char *pgsp_get_plan(dsm_segment *seg);
static void pgsp_cache_plan(PlannedStmt *custom, PlannedStmt *generic,
		pgspHashKey *key, double plantime, int num_const);
static uint32 pgsp_hash_fn(const void *key, Size keysize);
static int pgsp_match_fn(const void *key1, const void *key2, Size keysize);
static Size pgsp_memsize(void);
static pgspEntry *pgsp_entry_alloc(pgspHashKey *key, dsm_segment *seg,
		size_t len, double plantime, Cost custom_cost, Cost generic_cost,
		int num_const, int num_rels);
static void pgsp_entry_dealloc(void);
static void pgsp_entry_remove(pgspEntry *entry);
static bool pgsp_query_walker(Node *node, pgspWalkerContext *context);
static int entry_cmp(const void *lhs, const void *rhs);
static Datum do_showrels(dsm_segment *seg, int num_rels);
static char *do_showplans(dsm_segment *seg);


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

	DefineCustomIntVariable("pg_shared_plans.min_plan_time",
							"Sets the minimum planning time to save an entry (in ms).",
							NULL,
							&pgsp_min_plantime,
							10,
							0,
							INT_MAX,
							PGC_SUSET,
							GUC_UNIT_MS,
							NULL,
							NULL,
							NULL);

	DefineCustomIntVariable("pg_shared_plans.threshold",
							"Minimum number of custom plans to generate before maybe choosing cached plans.",
							NULL,
							&pgsp_threshold,
							5,
							1,
							INT_MAX,
							PGC_SUSET,
							0,
							NULL,
							NULL,
							NULL);

	DefineCustomBoolVariable("pg_shared_plans.explain_costs",
							 "Display plans with COST option.",
							 NULL,
							 &pgsp_es_costs,
							 false,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL);


	DefineCustomEnumVariable("pg_shared_plans.explain_format",
							 "Display plans with FORMAT option.",
							 NULL,
							 &pgsp_es_format,
							 EXPLAIN_FORMAT_TEXT,
							 pgsp_explain_format_options,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

	DefineCustomBoolVariable("pg_shared_plans.explain_verbose",
							 "Display plans with VERBOSE option.",
							 NULL,
							 &pgsp_es_verbose,
							 false,
							 PGC_SUSET,
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
		pgsp->cur_median_usage = ASSUMED_MEDIAN_INIT;
		SpinLockInit(&pgsp->mutex);
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
	instr_time		planstart,
					planduration;
	double			plantime;
	bool			accum_custom_stats = false;
	pgspWalkerContext context;

	if (!pgsp_enabled || parse->queryId == UINT64CONST(0) || boundParams == NULL)
		goto fallback;

	/* We need to create a per-user entry if there are RLS */
	if (parse->hasRowSecurity)
		key.userid = GetUserId();
	else
		key.userid = InvalidOid;
	key.dbid = MyDatabaseId;
	key.queryid = parse->queryId;

	/* Found unhandled nodes, don't try to cache the plan. */
	context.constid = 0;
	context.num_const = 0;
	/*
	 * Ignore if then plan is not cacheable (e.g. contains a temp table
	 * reference)
	 */
	if (pgsp_query_walker((Node *) parse, &context))
		goto fallback;

	key.constid = context.constid;

	/* Lookup the hash table entry with shared lock. */
	LWLockAcquire(pgsp->lock, LW_SHARED);
	entry = (pgspEntry *) hash_search(pgsp_hash, &key, HASH_FIND, NULL);

	if (entry)
	{
		dsm_segment *seg;
		char *local;

		Assert(entry->h != DSM_HANDLE_INVALID);

		seg = dsm_attach(entry->h);
		if (seg == NULL)
		{
			LWLockRelease(pgsp->lock);
			goto fallback;
		}

		local = pgsp_get_plan(seg);

		if (local != NULL)
		{
			bool	use_cached;

			use_cached = pgsp_choose_cache_plan(entry, &accum_custom_stats);

			if (use_cached)
			{
				result = (PlannedStmt *) stringToNode(local);

				dsm_detach(seg);
				LWLockRelease(pgsp->lock);
				pgsp_acquire_executor_locks(result, true);

				return result;
			}
		}
		else
		{
			/* Should not happen. */
			Assert(false);
		}

		dsm_detach(seg);
	}

	LWLockRelease(pgsp->lock);

	if (!entry)
	{
		generic_parse = copyObject(parse);
		INSTR_TIME_SET_CURRENT(planstart);
	}

	if (prev_planner_hook)
		result = (*prev_planner_hook) (parse, query_string, cursorOptions, boundParams);
	else
		result = standard_planner(parse, query_string, cursorOptions, boundParams);

	if(!entry)
	{
		INSTR_TIME_SET_CURRENT(planduration);
		INSTR_TIME_SUBTRACT(planduration, planstart);
		plantime = INSTR_TIME_GET_DOUBLE(planduration) * 1000.0;
	}

	/* Save the plan if no one did it yet */
	if (!entry && plantime > pgsp_min_plantime)
	{
		/* Generate a generic plan */
		generic = standard_planner(generic_parse, query_string, cursorOptions,
								   NULL);
		pgsp_cache_plan(result, generic, &key, plantime, context.num_const);
	}
	else if (accum_custom_stats)
	{
		Cost custom_cost = pgsp_cached_plan_cost(result, true);

		pgsp_accum_custom_plan(&key, custom_cost);
	}

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
	elog(DEBUG1, "pgsp_detach");
}

/* Release pgsp->lock that was acquired during pg_shared_plans(). */
static void
pg_shared_plans_shutdown(Datum arg)
{
	Assert(LWLockHeldByMeInMode(pgsp->lock, LW_SHARED));
	LWLockRelease(pgsp->lock);
}

/*
 * Accumulate statistics for custom planing.  Caller mustn't hold the LWLock.
 *
 * Note that even though caller should only call that function if the number of
 * custom plans hasn't reached pgsp_threshold, it may not be the case anymore
 * when we acquire the spinlock.  In that case we still accumulate the data as
 * we generated a custom plan, so it seems worthy to have more preciser
 * information about it.
 */
static void
pgsp_accum_custom_plan(pgspHashKey *key, Cost custom_cost)
{
	pgspEntry *entry;

	Assert(!LWLockHeldByMe(pgsp->lock));
	LWLockAcquire(pgsp->lock, LW_SHARED);

	entry = hash_search(pgsp_hash, key, HASH_FIND, NULL);
	if (entry)
	{
		volatile pgspEntry *e = (volatile pgspEntry *) entry;

		SpinLockAcquire(&e->mutex);
		e->total_custom_cost += custom_cost;
		e->num_custom_plans += 1;
		SpinLockRelease(&e->mutex);
	}

	LWLockRelease(pgsp->lock);
}

/*
 * Acquire locks needed for execution of a cached plan;
 * or release them if acquire is false.
 *
 * Based on AcquireExecutorLocks()
 */
static void
pgsp_acquire_executor_locks(PlannedStmt *plannedstmt, bool acquire)
{
	ListCell   *lc2;
	Index		rti,
				resultRelation = 0;

	if (plannedstmt->commandType == CMD_UTILITY)
	{
		/*
		 * Ignore utility statements, except those (such as EXPLAIN) that
		 * contain a parsed-but-not-planned query.  Note: it's okay to use
		 * ScanQueryForLocks, even though the query hasn't been through
		 * rule rewriting, because rewriting doesn't change the query
		 * representation.
		 */
		Query	   *query = UtilityContainsQuery(plannedstmt->utilityStmt);

		if (query)
			pgsp_ScanQueryForLocks(query, acquire);
		return;
	}

	rti = 1;
	if (plannedstmt->resultRelations)
		resultRelation = linitial_int(plannedstmt->resultRelations);
	foreach(lc2, plannedstmt->rtable)
	{
		RangeTblEntry *rte = (RangeTblEntry *) lfirst(lc2);

		if (rte->rtekind != RTE_RELATION)
			continue;

		/*
		 * Acquire the appropriate type of lock on each relation OID. Note
		 * that we don't actually try to open the rel, and hence will not
		 * fail if it's been dropped entirely --- we'll just transiently
		 * acquire a non-conflicting lock.
		 */
		if (acquire)
			LockRelationOid(rte->relid, rte->rellockmode);
		else
			UnlockRelationOid(rte->relid, rte->rellockmode);

		/* Lock partitions ahead of modifying them in parallel mode. */
		if (rti == resultRelation &&
			plannedstmt->partitionOids != NIL)
			pgsp_AcquireExecutorLocksOnPartitions(plannedstmt->partitionOids,
												  rte->rellockmode, acquire);

		rti++;
	}

}

static dsm_segment *
pgsp_allocate_plan(PlannedStmt *stmt, size_t *len, int *num_rels)
{
	dsm_segment *seg;
	shm_toc_estimator estimator;
	shm_toc *toc;
	char *local;
	char *serialized;
	size_t size, array_len;
	List	*oids = NIL;
	ListCell *lc;

	serialized = nodeToString(stmt);
	*len = strlen(serialized) + 1;

	/* Compute base relations the plan is referencing. */
	foreach(lc, stmt->rtable)
	{
		RangeTblEntry  *rte = lfirst_node(RangeTblEntry, lc);

		/* We only need to add dependency for real relations. */
		if (rte->rtekind != RTE_RELATION)
			continue;

		Assert(OidIsValid(rte->relid));
		oids = list_append_unique_oid(oids, rte->relid);
	}
	array_len = sizeof(Oid) * list_length(oids);
	*num_rels = list_length(oids);

	shm_toc_initialize_estimator(&estimator);
	shm_toc_estimate_keys(&estimator, 1);
	shm_toc_estimate_chunk(&estimator, *len);
	if (oids != NIL)
	{
		Assert(array_len >= sizeof(Oid));
		shm_toc_estimate_keys(&estimator, 1);
		shm_toc_estimate_chunk(&estimator, array_len);
	}
	size = shm_toc_estimate(&estimator);

	seg = dsm_create(size, DSM_CREATE_NULL_IF_MAXSEGMENTS);

	/* out of memory */
	if (!seg)
	{
		return NULL;
	}

	/* Save the serialized plan. */
	toc = shm_toc_create(PGSP_MAGIC, dsm_segment_address(seg), size);
	local = (char *) shm_toc_allocate(toc, *len);
	memcpy(local, serialized, *len);
	shm_toc_insert(toc, PGSP_PLAN_KEY, local);

	/* Save the list of Oids, if any. */
	if (oids != NIL)
	{
		Oid *array = (Oid *) shm_toc_allocate(toc, array_len);
		int i = 0;

		foreach(lc, oids)
			array[i++] = lfirst_oid(lc);

		shm_toc_insert(toc, PGSP_REL_KEY, array);
	}

	return seg;
}

/*
 * Decide whether to use a cached plan or not, and if caller should accumulate
 * custom plan statistics.
 * Also takes care of maintaining bypass and usage counters.
 * Caller must hold a shared lock on pgsp->lock.
 */
static bool
pgsp_choose_cache_plan(pgspEntry *entry, bool *accum_custom_stats)
{
	/* Grab the spinlock while updating the counters. */
	volatile pgspEntry *e = (volatile pgspEntry *) entry;
	bool				use_cached = false;

	Assert(LWLockHeldByMeInMode(pgsp->lock, LW_SHARED));

	/* We should already have computed a custom plan */
	Assert(e->generic_cost > 0 && e->len > 0 && e->h > 0 &&
		   e->plantime > 0);

	SpinLockAcquire(&e->mutex);

	if (e->num_custom_plans >= pgsp_threshold)
	{
		double				avg;

		avg = e->total_custom_cost / e->num_custom_plans;
		use_cached = (e->generic_cost < avg);

		if (use_cached)
		{
			e->bypass += 1;
			e->usage += e->plantime;
		}
	}
	else
	{
		/* Increment usage so that it doesn't get evicted too soon */
		e->usage += e->plantime;
		/* And tell caller to later accumulate custom plan statistics. */
		*accum_custom_stats = true;
	}
	SpinLockRelease(&e->mutex);

	return use_cached;
}

static char *
pgsp_get_plan(dsm_segment *seg)
{
	shm_toc *toc;

	Assert(seg);

	toc = shm_toc_attach(PGSP_MAGIC, dsm_segment_address(seg));
	Assert(toc);

	return (char *) shm_toc_lookup(toc, PGSP_PLAN_KEY, true);
}

/*
 * Store a generic plan in shared memory, and allocate a new entry to associate
 * the plan with.
 */
static void
pgsp_cache_plan(PlannedStmt *custom, PlannedStmt *generic, pgspHashKey *key,
				double plantime, int num_const)
{
	dsm_segment *seg;
	pgspEntry *entry PG_USED_FOR_ASSERTS_ONLY;
	size_t		len;
	int			num_rels;

	Assert(!LWLockHeldByMe(pgsp->lock));

	/*
	 * We store the plan is dsm before acquiring the lwlock.  It means that
	 * we may have to discard it, but it avoids locking overhead.
	 */
	seg = pgsp_allocate_plan(generic, &len, &num_rels);

	/*
	 * Don't try to allocate a new entry if we couldn't store the plan in
	 * dsm.
	 */
	if (!seg)
		return;

	LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);
	entry = pgsp_entry_alloc(key, seg, len, plantime,
							 pgsp_cached_plan_cost(custom, true),
							 pgsp_cached_plan_cost(generic, false),
							 num_const, num_rels);
	Assert(entry);
	LWLockRelease(pgsp->lock);
}

/* Calculate a hash value for a given key. */
static uint32
pgsp_hash_fn(const void *key, Size keysize)
{
	const pgspHashKey *k = (const pgspHashKey *) key;
	uint32 h;

	h = hash_combine(0, k->userid);
	h = hash_combine(h, k->dbid);
	h = hash_combine(h, k->queryid);
	h = hash_combine(h, k->constid);

	return h;
}

/* Compares two keys.  Zero means match. */
static int
pgsp_match_fn(const void *key1, const void *key2, Size keysize)
{
	const pgspHashKey *k1 = (const pgspHashKey *) key1;
	const pgspHashKey *k2 = (const pgspHashKey *) key2;

	if (k1->userid == k2->userid
		&& k1->dbid == k2->dbid
		&& k1->queryid == k2->queryid
		&& k1->constid == k2->constid
	)
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
 * Allocate a new hashtable entry if no one did the job before, and associate
 * it with the given dsm_segment that holds the generic plan for that entry.
 * Caller must hold an exclusive lock on pgsp->lock
 */
static pgspEntry *
pgsp_entry_alloc(pgspHashKey *key, dsm_segment *seg, size_t len,
		double plantime, Cost custom_cost, Cost generic_cost, int num_const,
		int num_rels)
{
	pgspEntry  *entry;
	bool		found;

	Assert(LWLockHeldByMeInMode(pgsp->lock, LW_EXCLUSIVE));

	/* Make space if needed */
	while (hash_get_num_entries(pgsp_hash) >= pgsp_max)
		pgsp_entry_dealloc();

	/* Find or create an entry with desired hash code */
	entry = (pgspEntry *) hash_search(pgsp_hash, key, HASH_ENTER, &found);

	if (!found)
	{
		/* New entry, initialize it */
		entry->len = len;
		entry->plantime = plantime;
		entry->bypass = 0;
		entry->usage = PGSP_USAGE_INIT;
		entry->total_custom_cost = custom_cost;
		entry->num_custom_plans = 1.0;
		entry->generic_cost = generic_cost;
		entry->num_const = num_const;
		entry->num_rels = num_rels;

		/* re-initialize the mutex each time ... we assume no one using it */
		SpinLockInit(&entry->mutex);

		/* permanently store the given dsm segment */
		entry->h = dsm_segment_handle(seg);
		dsm_pin_segment(seg);
		on_dsm_detach(seg, pgsp_detach, (Datum) 0);

		dsm_detach(seg);
	}

	/* We should always have a valid handle */
	Assert(entry->h != DSM_HANDLE_INVALID);

	return entry;
}

/*
 * Deallocate least-used entries.
 *
 * Caller must hold an exclusive lock on pgsp->lock.
 */
static void
pgsp_entry_dealloc(void)
{
	HASH_SEQ_STATUS hash_seq;
	pgspEntry **entries;
	pgspEntry  *entry;
	int			nvictims;
	int			i;

	Assert(LWLockHeldByMeInMode(pgsp->lock, LW_EXCLUSIVE));

	/*
	 * Sort entries by usage and deallocate USAGE_DEALLOC_PERCENT of them.
	 * While we're scanning the table, apply the decay factor to the usage
	 * values, and update the mean query length.
	 *
	 * Note that the mean query length is almost immediately obsolete, since
	 * we compute it before not after discarding the least-used entries.
	 * Hopefully, that doesn't affect the mean too much; it doesn't seem worth
	 * making two passes to get a more current result.  Likewise, the new
	 * cur_median_usage includes the entries we're about to zap.
	 */

	entries = palloc(hash_get_num_entries(pgsp_hash) * sizeof(pgspEntry *));

	i = 0;

	hash_seq_init(&hash_seq, pgsp_hash);
	while ((entry = hash_seq_search(&hash_seq)) != NULL)
	{
		entries[i++] = entry;
		entry->usage *= USAGE_DECREASE_FACTOR;
	}

	/* Sort into increasing order by usage */
	qsort(entries, i, sizeof(pgspEntry *), entry_cmp);

	/* Record the (approximate) median usage */
	if (i > 0)
		pgsp->cur_median_usage = entries[i / 2]->usage;

	/* Now zap an appropriate fraction of lowest-usage entries */
	nvictims = Max(10, i * USAGE_DEALLOC_PERCENT / 100);
	nvictims = Min(nvictims, i);

	for (i = 0; i < nvictims; i++)
	{
		pgspEntry *entry = entries[i];

		pgsp_entry_remove(entry);
	}

	pfree(entries);

	/* Increment the number of times entries are deallocated */
	{
		volatile pgspSharedState *s = (volatile pgspSharedState *) pgsp;

		SpinLockAcquire(&s->mutex);
		s->dealloc += 1;
		SpinLockRelease(&s->mutex);
	}
}

/* Remove an entry from the hash table and deallocate dsm segment. */
static void
pgsp_entry_remove(pgspEntry *entry)
{
	dsm_segment *seg;

	Assert(LWLockHeldByMeInMode(pgsp->lock, LW_EXCLUSIVE));

	/* Free the dsm segment. */
	seg = dsm_attach(entry->h);
	Assert(seg);
	dsm_unpin_segment(entry->h);
	dsm_detach(seg);

	/* And remove the hash entry. */
	hash_search(pgsp_hash, &entry->key, HASH_REMOVE, NULL);
}

/*
 * Walker function for query_tree_walker and expression_tree_walker to find
 * anything incompatible with shared plans.  The problematic things are:
 *
 * - usage of temporary tables
 *
 * It will also compute the constid, used to distinguish different queries
 * having the same queryid, in case multiple prepared statements have the same
 * normalized queries but with different hardcoded values.
 */
static bool
pgsp_query_walker(Node *node, pgspWalkerContext *context)
{
	if (!node)
		return false;

	if (IsA(node, Query))
	{
		Query *query = (Query *) node;
		ListCell *lc;

		foreach(lc, query->rtable)
		{
			RangeTblEntry *entry = lfirst_node(RangeTblEntry, lc);

			if (entry->rtekind == RTE_RELATION)
			{
				Relation rel = relation_open(entry->relid, AccessShareLock);
				bool is_temp;

				is_temp = RelationUsesLocalBuffers(rel);
				relation_close(rel, NoLock);

				if (is_temp)
					return true;
			}
		}

		return query_tree_walker(query, pgsp_query_walker, context, 0);
	}
	else if (IsA(node, Const))
	{
		char   *r = nodeToString(node);
		int		len = strlen(r);

		context->constid = hash_combine(context->constid,
										hash_any((unsigned char *) r, len));
		context->num_const++;
	}

	return expression_tree_walker(node, pgsp_query_walker, context);
}

/*
 * qsort comparator for sorting into increasing usage order
 */
static int
entry_cmp(const void *lhs, const void *rhs)
{
	double		l_usage = (*(pgspEntry *const *) lhs)->usage;
	double		r_usage = (*(pgspEntry *const *) rhs)->usage;

	if (l_usage < r_usage)
		return -1;
	else if (l_usage > r_usage)
		return +1;
	else
		return 0;
}

static Datum
do_showrels(dsm_segment *seg, int num_rels)
{
	Oid		   *array;
	shm_toc	   *toc;
	Datum	   *arrayelems;
	int			i;

	Assert(seg);
	Assert(num_rels > 0);

	toc = shm_toc_attach(PGSP_MAGIC, dsm_segment_address(seg));
	Assert(toc);

	array = (Oid *) shm_toc_lookup(toc, PGSP_REL_KEY, true);
	Assert(array);

	arrayelems = (Datum *) palloc(sizeof(Datum) * num_rels);

	for (i = 0; i < num_rels; i++)
		arrayelems[i] = ObjectIdGetDatum(array[i]);

	PG_RETURN_ARRAYTYPE_P(construct_array(arrayelems, num_rels, OIDOID,
						  sizeof(Oid), true, TYPALIGN_INT));
}

static char *
do_showplans(dsm_segment *seg)
{
	PlannedStmt *stmt;
	ExplainState   *es = NewExplainState();
	char *local;

	Assert(seg);

	local = pgsp_get_plan(seg);

	if (!local)
		return NULL;

	es->analyze = false;
	es->costs = pgsp_es_costs;
	es->verbose = pgsp_es_verbose;
	es->buffers = false;
	es->wal = false;
	es->timing = false;
	es->summary = false;
	es->format = pgsp_es_format;

	stmt = (PlannedStmt *) stringToNode(local);

	pgsp_acquire_executor_locks(stmt, true);
	ExplainBeginOutput(es);
	ExplainOnePlan(stmt, NULL, es, "", NULL, NULL, NULL, NULL);
	pgsp_acquire_executor_locks(stmt, false);

	return es->str->data;
}

Datum
pg_shared_plans_reset(PG_FUNCTION_ARGS)
{
	HASH_SEQ_STATUS hash_seq;
	pgspEntry  *entry;
	long		num_entries;
	long		num_remove = 0;
	//pgspHashKey key;
	Oid			userid;
	Oid			dbid;
	uint64		queryid;

	userid = PG_GETARG_OID(0);
	dbid = PG_GETARG_OID(1);
	queryid = (uint64) PG_GETARG_INT64(1);

	if (!pgsp || !pgsp_hash)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pg_shared_plans must be loaded via shared_preload_libraries")));

	LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);
	num_entries = hash_get_num_entries(pgsp_hash);

	/* No fastpath yet, should user care of a specific constid? */
	//if (userid != 0 && dbid != 0 && queryid != UINT64CONST(0))
	//{
	//	/* If all the parameters are available, use the fast path. */
	//	key.userid = userid;
	//	key.dbid = dbid;
	//	key.queryid = queryid;

	//	/* Remove the key if exists */
	//	entry = (pgspEntry *) hash_search(pgsp_hash, &key, HASH_FIND, NULL);

	//	if (entry)
	//	{
	//		pgsp_entry_remove(entry);
	//		num_remove++;
	//	}
	//}
	//else
	if (dbid != 0 || dbid != 0 || queryid != UINT64CONST(0))
	{
		/* Remove entries corresponding to valid parameters. */
		hash_seq_init(&hash_seq, pgsp_hash);
		while ((entry = hash_seq_search(&hash_seq)) != NULL)
		{
			if ((!userid || entry->key.userid == userid) &&
				(!dbid || entry->key.dbid == dbid) &&
				(!queryid || entry->key.queryid == queryid))
			{
				pgsp_entry_remove(entry);
				num_remove++;
			}
		}
	}
	else
	{
		/* Remove all entries. */
		hash_seq_init(&hash_seq, pgsp_hash);
		while ((entry = hash_seq_search(&hash_seq)) != NULL)
		{
			pgsp_entry_remove(entry);
			num_remove++;
		}
	}

	/* All entries are removed? */
	if (num_entries == num_remove)
	{
		volatile pgspSharedState *s = (volatile pgspSharedState *) pgsp;

		/*
		 * Reset global statistics for pg_shared_plans since all entries are
		 * removed.
		 */
		TimestampTz stats_reset = GetCurrentTimestamp();

		SpinLockAcquire(&s->mutex);
		s->dealloc = 0;
		s->stats_reset = stats_reset;
		SpinLockRelease(&s->mutex);
	}

	LWLockRelease(pgsp->lock);

	PG_RETURN_VOID();
}

/* Number of output arguments (columns) for pg_shared_plans_info */
#define PG_SHARED_PLANS_INFO_COLS	2

/*
 * Return statistics of pg_shared_plans.
 */
Datum
pg_shared_plans_info(PG_FUNCTION_ARGS)
{
	TupleDesc	tupdesc;
	Datum		values[PG_SHARED_PLANS_INFO_COLS];
	bool		nulls[PG_SHARED_PLANS_INFO_COLS];

	if (!pgsp || !pgsp_hash)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pg_shared_plans must be loaded via shared_preload_libraries")));

	/* Build a tuple descriptor for our result type */
	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	MemSet(values, 0, sizeof(values));
	MemSet(nulls, 0, sizeof(nulls));

	/* Read global statistics for pg_shared_plans */
	{
		volatile pgspSharedState *s = (volatile pgspSharedState *) pgsp;

		SpinLockAcquire(&s->mutex);
		values[0] = Int64GetDatum(s->dealloc);
		values[1] = TimestampTzGetDatum(s->stats_reset);
		SpinLockRelease(&s->mutex);
	}

	PG_RETURN_DATUM(HeapTupleGetDatum(heap_form_tuple(tupdesc, values, nulls)));
}

#define PG_SHARED_PLANS_COLS			14
Datum
pg_shared_plans(PG_FUNCTION_ARGS)
{
	struct
	{
		bool			showplan;
		HASH_SEQ_STATUS hash_seq;
	} *state;
	bool		showrels = PG_GETARG_BOOL(0);
	bool		showplan = PG_GETARG_BOOL(1);
	FuncCallContext *fctx;
	pgspEntry  *entry;

	if (SRF_IS_FIRSTCALL())
	{
		TupleDesc		tupdesc;
		ReturnSetInfo *rsi = (ReturnSetInfo *) fcinfo->resultinfo;
		MemoryContext	oldcontext;
		int				i = 1;

		/* create a function context for cross-call persistence */
		fctx = SRF_FIRSTCALL_INIT();

		oldcontext = MemoryContextSwitchTo(fctx->multi_call_memory_ctx);

		/* build tupdesc for result tuples */
		/* this had better match SQL definition in extension script */
		tupdesc = CreateTemplateTupleDesc(PG_SHARED_PLANS_COLS);
		TupleDescInitEntry(tupdesc, (AttrNumber) i++, "userid",
						   OIDOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) i++, "dbid",
						   OIDOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) i++, "queryid",
						   INT8OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) i++, "constid",
						   INT4OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) i++, "num_const",
						   INT4OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) i++, "bypass",
						   INT8OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) i++, "size",
						   INT8OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) i++, "plantime",
						   FLOAT8OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) i++, "total_custom_cost",
						   FLOAT8OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) i++, "num_custom_plans",
						   INT8OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) i++, "generic_cost",
						   FLOAT8OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) i++, "num_relations",
						   INT4OID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) i++, "relations",
						   OIDARRAYOID, -1, 0);
		TupleDescInitEntry(tupdesc, (AttrNumber) i++, "plans",
						   TEXTOID, -1, 0);

		Assert(i == PG_SHARED_PLANS_COLS + 1);
		fctx->tuple_desc = BlessTupleDesc(tupdesc);

		state = palloc(sizeof(*state));
		state->showplan = PG_GETARG_BOOL(0);

		MemoryContextSwitchTo(oldcontext);

		fctx->max_calls = hash_get_num_entries(pgsp_hash);
		fctx->user_fctx = state;

		/*
		 * Get shared lock and iterate over the hashtable entries.
		 *
		 * With a large hash table, we might be holding the lock rather longer
		 * than one could wish.  However, this only blocks creation of new hash
		 * table entries, and the larger the hash table the less likely that is
		 * to be needed.  So we can hope this is okay.  Perhaps someday we'll
		 * decide we need to partition the hash table to limit the time spent
		 * holding any one lock.
		 */
		LWLockAcquire(pgsp->lock, LW_SHARED);

		RegisterExprContextCallback(rsi->econtext,
				pg_shared_plans_shutdown,
				(Datum) 0);

		hash_seq_init(&state->hash_seq, pgsp_hash);
	}

	fctx = SRF_PERCALL_SETUP();
	state = fctx->user_fctx;

	if ((entry = hash_seq_search(&state->hash_seq)) != NULL)
	{
		HeapTuple	tuple;
		Datum		values[PG_SHARED_PLANS_COLS];
		bool		nulls[PG_SHARED_PLANS_COLS];
		int			i = 0;
		volatile pgspEntry *e = (volatile pgspEntry *) entry;
		int64		queryid;
		int64		bypass;
		int64		len;
		double		plantime;
		double		total_custom_cost;
		int64		num_custom_plans;
		double		generic_cost;

		Assert(fctx->call_cntr < fctx->max_calls);
		Assert(LWLockHeldByMeInMode(pgsp->lock, LW_SHARED));

		queryid = entry->key.queryid;
		len = entry->len;
		plantime = entry->plantime;
		generic_cost = entry->generic_cost;

		SpinLockAcquire(&e->mutex);
		bypass = entry->bypass;
		total_custom_cost = entry-> total_custom_cost;
		num_custom_plans = entry->num_custom_plans;
		SpinLockRelease(&e->mutex);

		memset(values, 0, sizeof(values));
		memset(nulls, 0, sizeof(nulls));

		if (OidIsValid(entry->key.userid))
			values[i++] = ObjectIdGetDatum(entry->key.userid);
		else
			nulls[i++] = true;
		values[i++] = ObjectIdGetDatum(entry->key.dbid);
		values[i++] = Int64GetDatumFast(queryid);
		if (OidIsValid(entry->key.constid))
			values[i++] = ObjectIdGetDatum(entry->key.constid);
		else
			nulls[i++] = true;
		values[i++] = Int32GetDatum(entry->num_const);
		values[i++] = Int64GetDatumFast(bypass);
		values[i++] = Int64GetDatumFast(len);
		values[i++] = Float8GetDatumFast(plantime);
		values[i++] = Float8GetDatumFast(total_custom_cost);
		values[i++] = Int64GetDatumFast(num_custom_plans);
		values[i++] = Float8GetDatumFast(generic_cost);
		values[i++] = Int32GetDatum(entry->num_rels);

		if (showplan || showrels)
		{
			dsm_segment *seg;

			seg = dsm_attach(entry->h);
			if (seg == NULL) /* should not happen */
			{
				nulls[i++] = true;
				values[i++] = CStringGetTextDatum("<no dsm_segment>");
			}
			else
			{
				if (showrels)
				{
					if (entry->num_rels == 0)
						nulls[i++] = true;
					else
						values[i++] = do_showrels(seg, entry->num_rels);
				}
				else
					nulls[i++] = true;
				if (showplan)
				{
					char *local = do_showplans(seg);

					if (local)
						values[i++] = CStringGetTextDatum(local);
					else
						values[i++] = CStringGetTextDatum("<no toc>");
				}
				else
					nulls[i++] = true;
			}
			dsm_detach(seg);
		}
		else
		{
			nulls[i++] = true;
			nulls[i++] = true;
		}
		Assert(i == PG_SHARED_PLANS_COLS);

		tuple = heap_form_tuple(fctx->tuple_desc, values, nulls);
		SRF_RETURN_NEXT(fctx, HeapTupleGetDatum(tuple));
	}

	/* LWLockRelease will be called in pg_shared_plans_shutdown(). */

	SRF_RETURN_DONE(fctx);
}
