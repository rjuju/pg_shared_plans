/*-------------------------------------------------------------------------
 *
 * pgsp_import.h: Import of some PostgreSQL private fuctions.
 *
 * This program is open source, licensed under the PostgreSQL license.
 * For license terms, see the LICENSE file.
 *
 * Copyright (c) 2008-2021, PostgreSQL Global Development Group
 *
 *-------------------------------------------------------------------------
 */

#ifndef _PGSP_IMPORT_H
#define _PGSP_IMPORT_H

#include "postgres.h"

#include "fmgr.h"
#include "funcapi.h"
#include "miscadmin.h"
#include "nodes/nodeFuncs.h"
#include "nodes/parsenodes.h"
#include "nodes/pg_list.h"
#include "storage/lmgr.h"

#if PG_VERSION_NUM < 130000
#define  TYPALIGN_INT			'i' /* int alignment (typically 4 bytes) */
#endif


void pgsp_AcquireExecutorLocksOnPartitions(List *partitionOids, int lockmode,
								 bool acquire);
void pgsp_ScanQueryForLocks(Query *parsetree, bool acquire);
bool pgsp_ScanQueryWalker(Node *node, bool *acquire);
double pgsp_cached_plan_cost(PlannedStmt *plannedstmt, bool include_planner);
#endif
