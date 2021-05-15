/*-------------------------------------------------------------------------
 *
 * pgsp_rdepend.h: Some functions to handle reverse dependencies on cached
 *                 plans.
 *
 * This program is open source, licensed under the PostgreSQL license.
 * For license terms, see the LICENSE file.
 *
 * Copyright (C) 2021: Julien Rouhaud
 *
 *-------------------------------------------------------------------------
 */

#ifndef _PGSP_RDEPEND_H
#define _PGSP_RDEPEND_H

#include "postgres.h"

#include "lib/dshash.h"
#include "nodes/nodes.h"
#include "storage/spin.h"

#include "include/pg_shared_plans.h"


#define PGSP_RDEPEND_INIT		10		/* default rdepend entry array size */

typedef struct pgspRdependKey
{
	Oid			dbid;
	Oid			classid;
	Oid			oid;
} pgspRdependKey;

/*
 * Store a reverse depdendency (in pgsp_rdepend dshash), from a relation to a
 * pgsp_hash entry.
 * Note that you can't assume that the stored pgspHashKey will point to an
 * existing entry, as pgsp->lock can be released between a reverse dependency
 * creation and the pgspEntry insertion.  This should however be a transient
 * situation.
 */
typedef struct pgspRdependEntry
{
	pgspRdependKey key;		/* hash key of the entry - MUST BE FIRST */
	int			num_keys;
	int			max_keys;
	dsa_pointer keys;		/* Hold an array of pgspHashKey */
} pgspRdependEntry;

extern dshash_parameters pgsp_rdepend_params;

bool pgsp_entry_register_rdepend(Oid dbid, Oid classid, Oid oid, pgspHashKey *key);
void pgsp_entry_unregister_rdepend(Oid dbid, Oid classid, Oid oid, pgspHashKey *key);

int pgsp_rdepend_fn_compare(const void *a, const void *b, size_t size,
								   void *arg);
dshash_hash pgsp_rdepend_fn_hash(const void *v, size_t size, void *arg);
#endif
