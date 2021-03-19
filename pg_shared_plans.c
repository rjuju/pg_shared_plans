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
#define PGSP_PLAN_KEY			UINT64CONST(1)
#define PGSP_USAGE_INIT			(1.0)
#define ASSUMED_MEDIAN_INIT		(10.0)	/* initial assumed median usage */
#define USAGE_DECREASE_FACTOR	(0.99)	/* decreased every entry_dealloc */
#define USAGE_DEALLOC_PERCENT	5		/* free this % of entries at once */

#define PGSP_LEVEL				DEBUG1

typedef struct pgspHashKey
{
	Oid			dbid;		/* database OID */
	uint64		queryid;	/* query identifier */
} pgspHashKey;

typedef struct pgspEntry
{
	pgspHashKey key;		/* hash key of entry - MUST BE FIRST */
	dsm_handle  h;			/* Only modified holding exclusive pgsp->lock */
	slock_t		mutex;		/* protects following fields only */
	double		usage;		/* usage factor */
} pgspEntry;

/*
 * Global shared state
 */
typedef struct pgspSharedState
{
	LWLock	   *lock;			/* protects hashtable search/modification */
	double		cur_median_usage;	/* current median usage in hashtable */
	slock_t		mutex;				/* protects following fields only */
	int64		dealloc;			/* # of times entries were deallocated */
} pgspSharedState;

/*---- Local variables ----*/

/* Saved hook values in case of unload */
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;
static planner_hook_type prev_planner_hook = NULL;

/* Links to shared memory state */
static pgspSharedState *pgsp = NULL;
static HTAB *pgsp_hash = NULL;

/*---- GUC variables ----*/

static bool pgsp_enabled = true;
static int	pgsp_max = 1000;

/*---- Function declarations ----*/

PGDLLEXPORT void _PG_init(void);
PGDLLEXPORT void _PG_fini(void);

PG_FUNCTION_INFO_V1(pg_shared_plans_reset);

static void pgsp_shmem_startup(void);
static PlannedStmt *pgsp_planner_hook(Query *parse,
									  const char *query_string,
									  int cursorOptions,
									  ParamListInfo boundParams);

static dsm_segment *pgsp_allocate_plan(PlannedStmt *stmt);
static void pgsp_detach(dsm_segment *segment, Datum datum);
static uint32 pgsp_hash_fn(const void *key, Size keysize);
static int pgsp_match_fn(const void *key1, const void *key2, Size keysize);
static Size pgsp_memsize(void);
static pgspEntry *pgsp_entry_alloc(pgspHashKey *key, dsm_segment *seg);
static void pgsp_entry_dealloc(void);
static int entry_cmp(const void *lhs, const void *rhs);


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

	if (entry && entry->h != DSM_HANDLE_INVALID)
	{
		dsm_segment *seg;
		shm_toc *toc;
		char *local;

		seg = dsm_attach(entry->h);
		if (seg == NULL)
		{
			LWLockRelease(pgsp->lock);
			goto fallback;
		}

		toc = shm_toc_attach(PGSP_MAGIC, dsm_segment_address(seg));
		local = (char *) shm_toc_lookup(toc, PGSP_PLAN_KEY, true);

		if (local != NULL)
		{
			elog(NOTICE, "found entry, bypassing planner");

			result = (PlannedStmt *) stringToNode(local);
			dsm_detach(seg);

			LWLockRelease(pgsp->lock);
			return result;
		}

		dsm_detach(seg);
	}
	else
		elog(PGSP_LEVEL, "entry not found :(");

	LWLockRelease(pgsp->lock);

	generic_parse = copyObject(parse);

	if (prev_planner_hook)
		result = (*prev_planner_hook) (parse, query_string, cursorOptions, boundParams);
	else
		result = standard_planner(parse, query_string, cursorOptions, boundParams);

	/* Also generate a generic plan */
	generic = standard_planner(generic_parse, query_string, cursorOptions, NULL);

	/* Save the plan if no one did it yet */
	if (!entry)
	{
		dsm_segment *seg;

		/*
		 * We store the plan is dsm before acquiring the lwlock.  It means that
		 * we may have to discard it, but it avoids locking overhead.
		 */
		seg = pgsp_allocate_plan(generic);

		/*
		 * Don't try to allocate a new entry if we couldn't store the plan in
		 * dsm.
		 */
		if (!seg)
			return result;

		LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);
		entry = pgsp_entry_alloc(&key, seg);
		LWLockRelease(pgsp->lock);
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

static dsm_segment *
pgsp_allocate_plan(PlannedStmt *stmt)
{
	dsm_segment *seg;
	shm_toc_estimator estimator;
	shm_toc *toc;
	char *local;
	char *serialized;
	size_t len, size;

	serialized = nodeToString(stmt);
	len = strlen(serialized) + 1;

	shm_toc_initialize_estimator(&estimator);
	shm_toc_estimate_keys(&estimator, 1);
	shm_toc_estimate_chunk(&estimator, len);
	size = shm_toc_estimate(&estimator);

	seg = dsm_create(size, DSM_CREATE_NULL_IF_MAXSEGMENTS);

	/* out of memory */
	if (!seg)
	{
		elog(PGSP_LEVEL, "out of mem");
		return NULL;
	}

	toc = shm_toc_create(PGSP_MAGIC, dsm_segment_address(seg), size);
	local = (char *) shm_toc_allocate(toc, len);
	memcpy(local, serialized, len);
	shm_toc_insert(toc, PGSP_PLAN_KEY, local);

	return seg;
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
pgsp_entry_alloc(pgspHashKey *key, dsm_segment *seg)
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
		entry->usage = PGSP_USAGE_INIT;

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

		/* Free the dsm segment. */
		dsm_segment *seg = dsm_attach(entry->h);
		Assert(seg);
		dsm_unpin_segment(entry->h);
		dsm_detach(seg);
		/* And remove the hash entry. */
		hash_search(pgsp_hash, &entry->key, HASH_REMOVE, NULL);
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

Datum
pg_shared_plans_reset(PG_FUNCTION_ARGS)
{
	PG_RETURN_VOID();
}
