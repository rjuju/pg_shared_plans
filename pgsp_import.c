/*-------------------------------------------------------------------------
 *
 * pspg_import.c: Import of some PostgreSQL private fuctions.
 *
 * This program is open source, licensed under the PostgreSQL license.
 * For license terms, see the LICENSE file.
 *
 * Copyright (c) 2008-2021, PostgreSQL Global Development Group
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "pgsp_import.h"

void
pgsp_AcquireExecutorLocksOnPartitions(List *partitionOids, int lockmode,
								 bool acquire)
{
	ListCell   *lc;

	foreach(lc, partitionOids)
	{
		Oid			partOid = lfirst_oid(lc);

		if (acquire)
			LockRelationOid(partOid, lockmode);
		else
			UnlockRelationOid(partOid, lockmode);
	}
}

/*
 * pgsp_ScanQueryForLocks: recursively scan one Query for AcquirePlannerLocks.
 */
void
pgsp_ScanQueryForLocks(Query *parsetree, bool acquire)
{
	ListCell   *lc;

	/* Shouldn't get called on utility commands */
	Assert(parsetree->commandType != CMD_UTILITY);

	/*
	 * First, process RTEs of the current query level.
	 */
	foreach(lc, parsetree->rtable)
	{
		RangeTblEntry *rte = (RangeTblEntry *) lfirst(lc);

		switch (rte->rtekind)
		{
			case RTE_RELATION:
				/* Acquire or release the appropriate type of lock */
				if (acquire)
					LockRelationOid(rte->relid, rte->rellockmode);
				else
					UnlockRelationOid(rte->relid, rte->rellockmode);
				break;

			case RTE_SUBQUERY:
				/* Recurse into subquery-in-FROM */
				pgsp_ScanQueryForLocks(rte->subquery, acquire);
				break;

			default:
				/* ignore other types of RTEs */
				break;
		}
	}

	/* Recurse into subquery-in-WITH */
	foreach(lc, parsetree->cteList)
	{
		CommonTableExpr *cte = lfirst_node(CommonTableExpr, lc);

		pgsp_ScanQueryForLocks(castNode(Query, cte->ctequery), acquire);
	}

	/*
	 * Recurse into sublink subqueries, too.  But we already did the ones in
	 * the rtable and cteList.
	 */
	if (parsetree->hasSubLinks)
	{
		query_tree_walker(parsetree, pgsp_ScanQueryWalker,
						  (void *) &acquire,
						  QTW_IGNORE_RC_SUBQUERIES);
	}
}

/*
 * Walker to find sublink subqueries for ScanQueryForLocks
 */
bool
pgsp_ScanQueryWalker(Node *node, bool *acquire)
{
	if (node == NULL)
		return false;
	if (IsA(node, SubLink))
	{
		SubLink    *sub = (SubLink *) node;

		/* Do what we came for */
		pgsp_ScanQueryForLocks(castNode(Query, sub->subselect), *acquire);
		/* Fall through to process lefthand args of SubLink */
	}

	/*
	 * Do NOT recurse into Query nodes, because ScanQueryForLocks already
	 * processed subselects of subselects for us.
	 */
	return expression_tree_walker(node, pgsp_ScanQueryWalker,
								  (void *) acquire);
}
