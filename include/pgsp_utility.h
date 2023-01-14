/*-------------------------------------------------------------------------
 *
 * pgsp_utility.h: Function used in pgsp_utility hook.
 *
 * This program is open source, licensed under the PostgreSQL license.
 * For license terms, see the LICENSE file.
 *
 * Copyright (C) 2021-2023: Julien Rouhaud
 *
 *-------------------------------------------------------------------------
 */

#ifndef _PGSP_UTILITY_H
#define _PGSP_UTILITY_H

#include "postgres.h"

#include "nodes/nodes.h"

#include "include/pgsp_rdepend.h"

typedef struct pgspOidsKey
{
	pgspEvictionKind kind;
	Oid classid;
} pgspOidsKey;

typedef struct pgspOidsEntry
{
	pgspOidsKey key;
	List	   *oids;
} pgspOidsEntry;

typedef struct pgspUtilityContext
{
	HTAB   *oids_hash;
	bool	has_discard;
	bool	has_remove;
	bool	has_lock;
	bool	reset_current_db;
} pgspUtilityContext;

void pgsp_utility_do_lock(pgspUtilityContext *c);
void pgsp_utility_pre_exec(Node *parsetree, pgspUtilityContext *c);
void pgsp_utility_post_exec(Node *parsetree, pgspUtilityContext *c);

#endif
