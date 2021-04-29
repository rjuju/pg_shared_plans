/*-------------------------------------------------------------------------
 *
 * pspg_inherit.c: Some functions to handle inheritance children.
 *
 * This program is open source, licensed under the PostgreSQL license.
 * For license terms, see the LICENSE file.
 *
 * Copyright (C) 2021: Julien Rouhaud
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/genam.h"
#include "access/table.h"
#if PG_VERSION_NUM < 140000
#include "catalog/indexing.h"
#endif
#include "catalog/pg_inherits.h"
#include "nodes/pg_list.h"
#include "utils/fmgroids.h"
#include "utils/relcache.h"

#include "include/pgsp_import.h"
#include "include/pgsp_inherit.h"


static void pgsp_get_inheritance_ancestors_worker(Relation inhRel, Oid relid,
												   List **ancestors);
static List *pgsp_get_inheritance_parent_worker(Relation inhRel, Oid relid);

/*
 * Modified version of get_partition_ancestors to work with relations having
 * multiple ancestors.
 */
List *
pgsp_get_inheritance_ancestors(Oid relid)
{
	List *result = NIL;
	Relation inhRel;

	inhRel = table_open(InheritsRelationId, AccessShareLock);

	pgsp_get_inheritance_ancestors_worker(inhRel, relid, &result);

	table_close(inhRel, AccessShareLock);

	return result;
}

static void
pgsp_get_inheritance_ancestors_worker(Relation inhRel, Oid relid,
									  List **ancestors)
{
	List	 *parentOids;
	ListCell *lc;

	/*
	 * Recursion ends at the topmost level, ie., when there's no parent.
	 */
	parentOids = pgsp_get_inheritance_parent_worker(inhRel, relid);
	if (parentOids == NIL)
		return;

	foreach(lc, parentOids)
	{
		Oid parentOid = lfirst_oid(lc);

		if (list_member_oid(*ancestors, parentOid))
			continue;

		*ancestors = lappend_oid(*ancestors, parentOid);
		pgsp_get_inheritance_ancestors_worker(inhRel, parentOid, ancestors);
	}
}

static List *
pgsp_get_inheritance_parent_worker(Relation inhRel, Oid relid)
{
	SysScanDesc scan;
	ScanKeyData key[1];
	List	   *result = NIL;
	HeapTuple	tuple;

	ScanKeyInit(&key[0],
				Anum_pg_inherits_inhrelid,
				BTEqualStrategyNumber, F_OIDEQ,
				ObjectIdGetDatum(relid));

	scan = systable_beginscan(inhRel, InheritsRelidSeqnoIndexId, true,
							  NULL, 1, key);

	while ((tuple = systable_getnext(scan)) != NULL)
	{
		Form_pg_inherits form = (Form_pg_inherits) GETSTRUCT(tuple);

		result = lappend_oid(result, form->inhparent);
	}

	systable_endscan(scan);

	return result;
}
