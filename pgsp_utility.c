/*-------------------------------------------------------------------------
 *
 * pgsp_utility.h: Function used in pgsp_utility hook.
 *
 * This program is open source, licensed under the PostgreSQL license.
 * For license terms, see the LICENSE file.
 *
 * Copyright (C) 2021: Julien Rouhaud
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/xact.h"
#include "catalog/index.h"
#include "catalog/namespace.h"
#include "catalog/partition.h"
#include "catalog/pg_class.h"
#include "catalog/pg_inherits.h"
#include "commands/tablecmds.h"
#include "nodes/makefuncs.h"
#include "nodes/nodes.h"
#include "nodes/parsenodes.h"
#include "nodes/pg_list.h"
#include "parser/parse_type.h"
#include "storage/lwlock.h"
#include "utils/lsyscache.h"
#include "utils/snapmgr.h"
#include "utils/syscache.h"

#include "include/pg_shared_plans.h"
#include "include/pgsp_inherit.h"
#include "include/pgsp_rdepend.h"
#include "include/pgsp_utility.h"

static void init_oids(pgspUtilityContext *c);
static pgspOidsEntry *get_oids_entry(pgspEvictionKind kind, Oid classid,
									 pgspUtilityContext *c);
static void discard_oid(Oid classid, Oid oid, pgspUtilityContext *c);
static void discard_oids(Oid classid, List *oids, pgspUtilityContext *c);
static void lock_oid(Oid classid, Oid oid, pgspUtilityContext *c);
static void lock_oids(Oid classid, List *oids, pgspUtilityContext *c);
static void remove_oid(Oid classid, Oid oid, pgspUtilityContext *c);

static void
init_oids(pgspUtilityContext *c)
{
	HASHCTL		info;

	if (c->oids_hash != NULL)
		return;

	memset(&info, 0, sizeof(HASHCTL));
	info.keysize = sizeof(pgspOidsKey);
	info.entrysize = sizeof(pgspOidsEntry);

	c->oids_hash= hash_create("pg_shared_plans oids", 10, &info,
							  HASH_ELEM | HASH_BLOBS);
}

static pgspOidsEntry *
get_oids_entry(pgspEvictionKind kind, Oid classid, pgspUtilityContext *c)
{
	pgspOidsKey		key = {kind, classid};
	pgspOidsEntry  *entry;
	bool			found;

	init_oids(c);
	entry = hash_search(c->oids_hash, &key, HASH_ENTER, &found);

	if (!found)
		entry->oids = NIL;

	return entry;
}

static void
discard_oid(Oid classid, Oid oid, pgspUtilityContext *c)
{
	pgspOidsEntry *entry;

	if (!OidIsValid(oid))
		return;

	entry = get_oids_entry(PGSP_DISCARD, classid, c);

	entry->oids = list_append_unique_oid(entry->oids, oid);
	c->has_discard = true;
}

static void
discard_oids(Oid classid, List *oids, pgspUtilityContext *c)
{
	pgspOidsEntry *entry;

	if (oids == NIL)
		return;

	entry = get_oids_entry(PGSP_DISCARD, classid, c);
	entry->oids = list_concat_unique_oid(entry->oids, oids);
	c->has_discard = true;
}

static void
lock_oid(Oid classid, Oid oid, pgspUtilityContext *c)
{
	pgspOidsEntry *entry;

	if (!OidIsValid(oid))
		return;

	entry = get_oids_entry(PGSP_DISCARD_AND_LOCK, classid, c);
	entry->oids = list_append_unique_oid(entry->oids, oid);
	c->has_lock = true;
}

static void
lock_oids(Oid classid, List *oids, pgspUtilityContext *c)
{
	pgspOidsEntry *entry;

	if (oids == NIL)
		return;

	entry = get_oids_entry(PGSP_DISCARD_AND_LOCK, classid, c);
	entry->oids = list_concat_unique_oid(entry->oids, oids);
	c->has_lock = true;
}

static void
remove_oid(Oid classid, Oid oid, pgspUtilityContext *c)
{
	pgspOidsEntry *entry;

	if (!OidIsValid(oid))
		return;

	entry = get_oids_entry(PGSP_EVICT, classid, c);
	entry->oids = list_append_unique_oid(entry->oids, oid);
	c->has_remove = true;
}

/* For UTILITY with CONCURRENTLY option, the altered object property will be
 * changed in the middle of the execution, with no AEL kept long enough to
 * protect our cache.  So the best we can do since we can't hook on the catalog
 * invalidation infrastructure is to
 *  - discard the cache now
 *  - lock the dependent entries to prevent any new plan to be saved
 *  - downgrade the lock on pgsp->lock while the entries are lock
 *  - hold that shared lock until after standard_ProcessUtility execution and
 *    hope this backend won't be killed while the entries are locked, otherwise
 *    they would be locked until they get evicted, either automatically or
 *    manually.
 */
void
pgsp_utility_do_lock(pgspUtilityContext *c)
{
	pgspOidsEntry  *entry;
	HASH_SEQ_STATUS oids_seq;

	if (!c->has_lock)
		return;

	Assert(!c->has_discard && !c->has_remove);
	Assert(c->oids_hash != NULL);

	hash_seq_init(&oids_seq, c->oids_hash);
	while ((entry = hash_seq_search(&oids_seq)) != NULL)
	{
		ListCell *lc;

		/* Should not find other discard kind, but be safe. */
		if (entry->key.kind != PGSP_DISCARD_AND_LOCK)
			continue;

		Assert(entry->oids != NIL);

		LWLockAcquire(pgsp->lock, LW_EXCLUSIVE);

		foreach(lc, entry->oids)
			pgsp_evict_by_oid(MyDatabaseId, entry->key.classid, lfirst_oid(lc),
							  PGSP_DISCARD_AND_LOCK);

		/*
		 * Downgrade the lock.  We locked all the underlying entries so there's
		 * no risk of having another backend caching a new plan before the
		 * index is really dropped.  There's however a risk that the entry
		 * gets evicted and recreated before acquiring the shared lock on
		 * pgsp->lock, leaving the new entry indefinitely locked.
		 */
		LWLockRelease(pgsp->lock);
		LWLockAcquire(pgsp->lock, LW_SHARED);

		foreach(lc, entry->oids)
			pgsp_evict_by_oid(MyDatabaseId, entry->key.classid, lfirst_oid(lc),
							  PGSP_UNLOCK);
	}
}

/*
 * Process all nodes that have to be processed before the UTILITY
 * execution:
 *
 * - DROP commands
 * - ALTER TABLE DETACH PARTITION CONCURRENTLY
 * - sanity check for ALTER TEXT SEARCH DICTIONNARY
 */
void
pgsp_utility_pre_exec(Node *parsetree, pgspUtilityContext *c)
{
	if (IsA(parsetree, DropStmt))
	{
		DropStmt *drop = (DropStmt *) parsetree;
		List     *objs_remove = NIL;
		ListCell *cell;

		switch (drop->removeType)
		{
			/* For indexes we need to get the underlying table instead. */
			case OBJECT_INDEX:
			{
				/*
				 * Don't mess  up with the transactions if the command is gonna
				 * fail.
				 */
				if (drop->concurrent &&
					(GetTopTransactionIdIfAny() != InvalidTransactionId ||
					 IsTransactionBlock())
				)
					return;

				foreach(cell, drop->objects)
				{
					List *name = (List *) lfirst(cell);
					RangeVar *rel = makeRangeVarFromNameList(name);
					Oid			indoid, heapoid;

					/*
					 * XXX: is it really ok to ignore permissions here, as
					 * standard_ProcessUtility will fail before we actually use
					 * the generated list?
					 */
					indoid = RangeVarGetRelidExtended(rel, AccessExclusiveLock,
							RVR_MISSING_OK, NULL, NULL);
					if (!OidIsValid(indoid))
						break; /* XXX can that happen? */

					heapoid = IndexGetRelation(indoid, true);
					if (!OidIsValid(heapoid))
						break; /* XXX can that happen? */

					/*
					 * Got the root table, directly add its oid to the discard
					 * list.  We assume that a generic plan will still be a
					 * good idea after the index is removed.
					 */
					if (drop->concurrent)
						lock_oid(RELOID, heapoid, c);
					else
						discard_oid(RELOID, heapoid, c);

					/*
					 * CIC expects to be the first command in a transaction, so
					 * commit the transaction that we just started when looking
					 * for the root table name and start a fresh one.
					 */
					if (drop->concurrent)
					{
						MemoryContext	oldcontext = CurrentMemoryContext;

						PopActiveSnapshot();
						CommitTransactionCommand();
						StartTransactionCommand();
						MemoryContextSwitchTo(oldcontext);
						PushActiveSnapshot(GetTransactionSnapshot());
					}
				}
				break;
			}
			case OBJECT_FOREIGN_TABLE:
			case OBJECT_MATVIEW:
			case OBJECT_TABLE:
			case OBJECT_VIEW:
				/* Handled types. */
				objs_remove = drop->objects;
				break;
			default:
				/* nothing to do. */
				break;
		}

		foreach(cell, objs_remove)
		{
			RangeVar   *rel = makeRangeVarFromNameList((List *) lfirst(cell));
			Oid         oid;

			oid = RangeVarGetRelidExtended(rel, AccessShareLock,
					RVR_MISSING_OK, NULL, NULL);

			if (OidIsValid(oid))
				remove_oid(RELOID, oid, c);
		}
	}
	else if (IsA(parsetree, AlterTableStmt))
	{
		AlterTableStmt *atstmt = (AlterTableStmt *) parsetree;
		LOCKMODE lockmode;
		ListCell *lc;

		lockmode = AlterTableGetLockLevel(atstmt->cmds);

		foreach(lc, atstmt->cmds)
		{
			AlterTableCmd *cmd = (AlterTableCmd *) lfirst(lc);

			if (cmd->subtype == AT_DetachPartition
					&& ((PartitionCmd *)cmd->def)->concurrent
			)
			{
				Oid oid;

				/* Ignore if the command is gonna fail. */
				if (IsTransactionBlock())
					return;

				oid = AlterTableLookupRelation(atstmt, lockmode);

				if (OidIsValid(oid))
				{
					/*
					 * For attaching a partition, we only need to discard plans
					 * depending on the referenced partitioned table and its
					 * ancestors.
					 */
					lock_oid(RELOID, oid, c);
					lock_oids(RELOID, get_partition_ancestors(oid), c);
				}
			}
		}
	}
	else if (IsA(parsetree, AlterTSDictionaryStmt))
	{
		/* We have no way to track dependencies on TEXT SEARCH DICTIONNARY, so
		 * the only way to avoid returning false result is to entirely drop the
		 * cache for the current database.  Hopefully such commands should not
		 * be frequent so it won't be a big issue.
		 * Note that to properly test this behavior you need multiple backends
		 * as the one executing the ALTER TEXT SEARCH DICTIONNARY wilL discard
		 * his own cache.
		 * Note also that to ensure a correct behavior we have to make sure
		 * that the command isn't run in a transaction (done here), and we will
		 * only drop the cached plans after the UTILITY has been executed.
		 * XXX It's still possible that someone locally deactivate
		 *     pg_shared_plans before executing such a command, which would be
		 *     bad, or that another backend cache a new plan between the reset
		 *     and the commit of the ALTER TEXT SELECT DICTIONARY.
		*/
		if(IsTransactionBlock())
			elog(ERROR, "pg_shared_plans: can't run ALTER TEXT SEARCH"
					" DICTIONNARY in a transaction.");
		c->reset_current_db = true;
	}
}

void
pgsp_utility_post_exec(Node *parsetree, pgspUtilityContext *c)
{
	Assert(!c->reset_current_db);

	if (IsA(parsetree, AlterTableStmt))
	{
		AlterTableStmt *atstmt = (AlterTableStmt *) parsetree;
		LOCKMODE    lockmode;

		/*
		 * Any change that requires an AccessExclusiveLock should impact the
		 * plan.  We assume that it's better to discard the plans only, hoping
		 * that there will be more entries which will still be valid after the
		 * ALTER TABLE.
		 * Attaching / detaching partitions also requires cache invalidation.
		 * Note that CONCURRENT detaching is handled before the UTILITY
		 * execution due to its non-transactional nature.
		 */
		lockmode = AlterTableGetLockLevel(atstmt->cmds);
		if (lockmode >= AccessExclusiveLock)
		{
			Oid		oid = AlterTableLookupRelation(atstmt, lockmode);

			if (OidIsValid(oid))
			{
				discard_oid(RELOID, oid, c);

				/*
				 * We must also discard any plans depending on ancestors, if
				 * any.
				 */
				discard_oids(RELOID, pgsp_get_inheritance_ancestors(oid), c);

				/* And inheritors, if it's not a DETACH PARTITION. */
				if (list_length(atstmt->cmds) == 1 &&
						((AlterTableCmd *) linitial(atstmt->cmds))->subtype !=
						AT_DetachPartition)
				{
					discard_oids(RELOID,
								 find_all_inheritors(oid, AccessShareLock, NULL),
								 c);
				}
			}
		}
		else
		{
			ListCell *lc;

			foreach(lc, atstmt->cmds)
			{
				AlterTableCmd *cmd = (AlterTableCmd *) lfirst(lc);

				if (cmd->subtype == AT_AttachPartition ||
					cmd->subtype == AT_DetachPartitionFinalize ||
					(cmd->subtype == AT_DetachPartition
						&& !((PartitionCmd *)cmd->def)->concurrent)
				)
				{
					Oid oid = AlterTableLookupRelation(atstmt, lockmode);

					/* This should require an exclusive lock. */
					Assert(cmd->subtype != AT_DetachPartition);

					if (OidIsValid(oid))
					{
						/*
						 * For attaching/detaching a partition, we only need to
						 * discard plans depending on the referenced
						 * partitioned table and its ancestors.
						 */
						discard_oid(RELOID, oid, c);
						discard_oids(RELOID, get_partition_ancestors(oid), c);
					}
				}
			}
		}
	}
	else if (IsA(parsetree, IndexStmt))
	{
		IndexStmt  *stmt = (IndexStmt *) parsetree;
		Oid			relid;

		relid = RangeVarGetRelidExtended(stmt->relation, AccessExclusiveLock,
				RVR_MISSING_OK, NULL, NULL);

		Assert(OidIsValid(relid));
		discard_oid(RELOID, relid, c);

		/* We need to discard cache for all ancestors */
		discard_oids(RELOID, pgsp_get_inheritance_ancestors(relid), c);

		/* And also for all inheritors if it's a partitioned table. */
		if (get_rel_relkind(relid) == RELKIND_PARTITIONED_TABLE)
			discard_oids(RELOID,
						 find_all_inheritors(relid, AccessShareLock, NULL), c);
	}
	else if (IsA(parsetree, CreateStmt))
	{
		CreateStmt *stmt = (CreateStmt *) parsetree;
		ListCell   *lc;

		/*
		 * If it's an inheritance children, discard all caches depending on any
		 * of the ancestors.
		 */
		foreach(lc, stmt->inhRelations)
		{
			RangeVar   *rv = (RangeVar *) lfirst(lc);
			Oid			oid;

			oid = RangeVarGetRelidExtended(rv, AccessShareLock, RVR_MISSING_OK,
					NULL, NULL);
			Assert(OidIsValid(oid));
			discard_oid(RELOID, oid, c);

			if (stmt->ofTypename)
				discard_oids(RELOID, get_partition_ancestors(oid), c);
			else
				discard_oids(RELOID, pgsp_get_inheritance_ancestors(oid), c);
		}
	}
	else if (IsA(parsetree, AlterDomainStmt))
	{
		AlterDomainStmt	   *atd = (AlterDomainStmt *) parsetree;
		TypeName		   *typename;
		Oid					domainoid;
		uint32				hashValue;

		/* Make a TypeName so we can use standard type lookup machinery */
		typename = makeTypeNameFromNameList(atd->typeName);
		domainoid = typenameTypeId(NULL, typename);

		Assert(OidIsValid(domainoid));

		/*
		 * Saved type dependencies are done using standard PlanInvalItem
		 * infrastructure which doesn't track the oid but its hash value, so we
		 * have to discard plans using the same hash value.
		 */
		hashValue = GetSysCacheHashValue1(TYPEOID, ObjectIdGetDatum(domainoid));
		discard_oid(TYPEOID, hashValue, c);
	}
}
