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

#include "optimizer/optimizer.h"

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

/*
 * cached_plan_cost: calculate estimated cost of a plan
 *
 * If include_planner is true, also include the estimated cost of constructing
 * the plan.  (We must factor that into the cost of using a custom plan, but
 * we don't count it for a generic plan.)
 */
double
pgsp_cached_plan_cost(PlannedStmt *plannedstmt, bool include_planner)
{
	double		result = 0;

	if (plannedstmt->commandType == CMD_UTILITY)
		return result;			/* Ignore utility statements */

	result += plannedstmt->planTree->total_cost;

	if (include_planner)
	{
		/*
		 * Currently we use a very crude estimate of planning effort based
		 * on the number of relations in the finished plan's rangetable.
		 * Join planning effort actually scales much worse than linearly
		 * in the number of relations --- but only until the join collapse
		 * limits kick in.  Also, while inheritance child relations surely
		 * add to planning effort, they don't make the join situation
		 * worse.  So the actual shape of the planning cost curve versus
		 * number of relations isn't all that obvious.  It will take
		 * considerable work to arrive at a less crude estimate, and for
		 * now it's not clear that's worth doing.
		 *
		 * The other big difficulty here is that we don't have any very
		 * good model of how planning cost compares to execution costs.
		 * The current multiplier of 1000 * cpu_operator_cost is probably
		 * on the low side, but we'll try this for awhile before making a
		 * more aggressive correction.
		 *
		 * If we ever do write a more complicated estimator, it should
		 * probably live in src/backend/optimizer/ not here.
		 */
		int			nrelations = list_length(plannedstmt->rtable);

		result += 1000.0 * cpu_operator_cost * (nrelations + 1);
	}

	return result;
}
