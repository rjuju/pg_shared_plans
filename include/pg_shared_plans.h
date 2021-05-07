/*-------------------------------------------------------------------------
 *
 * pg_shared_plans.h: Implementation of plan cache in shared memoery.
 *
 * This program is open source, licensed under the PostgreSQL license.
 * For license terms, see the LICENSE file.
 *
 * Copyright (C) 2021: Julien Rouhaud
 *
 *-------------------------------------------------------------------------
 */

#ifndef _PG_SHARED_PLANS_H
#define _PG_SHARED_PLANS_H

#include "postgres.h"

#include "datatype/timestamp.h"
#include "lib/dshash.h"
#include "miscadmin.h"
#include "storage/s_lock.h"
#include "utils/hsearch.h"


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
	size_t		len;		/* serialized plan length */
	dsa_pointer plan;		/* only modified holding exclusive pgsp->lock */
	int			num_rels;	/* # of referenced base relations */
	dsa_pointer rels;		/* only modified holding exclusive pgsp->lock */
	int			num_rdeps;	/* # of non relation reverse dependencies */
	dsa_pointer rdeps;		/* array of pgspRdependKey - only modified holding
							   exclusive pgsp_lock */
	int			num_const;	/* # of const values in the plan */
	double		plantime;	/* first generic planning time */
	Cost		generic_cost; /* total cost of the stored plan */
	int64		discard;	/* # of time plan was discarded */
	pg_atomic_uint32 lockers;/* prevent new plans from being saved if > 0 */
	slock_t		mutex;		/* protects following fields only */
	int64		bypass;		/* number of times magic happened */
	double		usage;		/* usage factor */
	Cost		total_custom_cost; /* total cost of custom plans planned */
	int64		num_custom_plans; /* # of custom plans planned */
} pgspEntry;

typedef enum pgspEvictionKind
{
	PGSP_UNLOCK,
	PGSP_DISCARD,
	PGSP_DISCARD_AND_LOCK,
	PGSP_EVICT
} pgspEvictionKind;

/*
 * Global shared state
 */
typedef struct pgspSharedState
{
	LWLock	   *lock;			/* protects all hashtable search/modification */
	int			LWTRANCHE_PGSP;
	dsa_handle	pgsp_dsa_handle;
	dshash_table_handle pgsp_rdepend_handle;
	double		cur_median_usage;	/* current median usage in hashtable */
	slock_t		mutex;				/* protects following fields only */
	int64		dealloc;			/* # of times entries were deallocated */
	TimestampTz stats_reset;		/* timestamp with all stats reset */
} pgspSharedState;

/* Links to shared memory state */
extern pgspSharedState *pgsp;
extern HTAB *pgsp_hash;
extern dsa_area *pgsp_area;
extern dshash_table *pgsp_rdepend;

uint32 pgsp_hash_fn(const void *key, Size keysize);
int pgsp_match_fn(const void *key1, const void *key2, Size keysize);

void pgsp_evict_by_oid(Oid dbid, Oid classid, Oid oid, pgspEvictionKind kind);

#endif
