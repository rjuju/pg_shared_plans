/*-------------------------------------------------------------------------
 *
 * pspg_rdepend.c: Some functions to handle reverse dependencies on cached
 *                 plans.
 *
 * This program is open source, licensed under the PostgreSQL license.
 * For license terms, see the LICENSE file.
 *
 * Copyright (C) 2021: Julien Rouhaud
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "commands/dbcommands.h"
#include "storage/lwlock.h"
#if PG_VERSION_NUM >= 130000
#include "common/hashfn.h"
#else
#include "utils/hashutils.h"
#endif
#include "utils/lsyscache.h"

#include "include/pgsp_rdepend.h"

/*
 * Add a reverse depdency for a (dbid, relid) on the given pgspEntry,
 * identified by its key.
 */
bool
pgsp_entry_register_rdepend(Oid dbid, Oid relid, pgspHashKey *key)
{
	pgspRdependKey rkey = {dbid, relid};
	pgspRdependEntry   *rentry;
	pgspHashKey			*rkeys;
	bool				found;
	int					i;

	/* Note that even though we hold an exlusive lock on pgsp->lock, it will
	 * eventually be released before the related entry is inserted in the main
	 * hash table.
	 */
	Assert(LWLockHeldByMeInMode(pgsp->lock, LW_EXCLUSIVE));
	Assert(area != NULL && pgsp_rdepend != NULL);

	rentry = dshash_find_or_insert(pgsp_rdepend, &rkey, &found);

	if (!found)
	{
		rentry->max_keys = PGSP_RDEPEND_INIT;
		rentry->num_keys = 0;
		rentry->keys = dsa_allocate_extended(area,
				sizeof(pgspHashKey) * PGSP_RDEPEND_INIT,
				DSA_ALLOC_NO_OOM);

		if (rentry->keys == InvalidDsaPointer)
		{
			dshash_delete_entry(pgsp_rdepend, rentry);

			return false;
		}
	}
	Assert(rentry->keys != InvalidDsaPointer);

	if (rentry->num_keys >= rentry->max_keys)
	{
		dsa_pointer new_rkeys_p;
		pgspHashKey *new_rkeys;
		int new_max_keys = Max(rentry->max_keys * 2, PGSP_RDEPEND_MAX);

		/*
		 * Too many rdepend entries for this relation, refuse to create a new
		 * pgspEntry and raise a WARNING.
		 * XXX should PGSP_RDEPEND_MAX be exposed as a GUC?
		 */
		if (rentry->num_keys >= PGSP_RDEPEND_MAX)
		{
			elog(WARNING, "pgsp: Too many cache entries for relation \"%s\""
					" on database \"%s\"",
					get_rel_name(relid), get_database_name(dbid));

			dshash_release_lock(pgsp_rdepend, rentry);
			return false;
		}

		rkeys = (pgspHashKey *) dsa_get_address(area, rentry->keys);
		Assert(rkeys != NULL);

		new_rkeys_p = dsa_allocate_extended(area,
											sizeof(pgspHashKey) * new_max_keys,
											DSA_ALLOC_NO_OOM);
		if (new_rkeys_p == InvalidDsaPointer)
		{
			elog(WARNING, "pgsp: Could not cache entries for relation \"%s\""
					" on database \"%s\": out of shared memory",
					get_rel_name(relid), get_database_name(dbid));

			dshash_release_lock(pgsp_rdepend, rentry);
			return false;
		}

		new_rkeys = (pgspHashKey *) dsa_get_address(area, new_rkeys_p);
		Assert(new_rkeys != NULL);

		memcpy(new_rkeys, rkeys, sizeof(pgspHashKey) * new_max_keys);
		rkeys = NULL;
		dsa_free(area, rentry->keys);

		rentry->keys = new_rkeys_p;
		rentry->max_keys = new_max_keys;
	}

	rkeys = (pgspHashKey *) dsa_get_address(area, rentry->keys);
	Assert(rkeys != NULL);

	/* Check first if the rdepend is already registered */
	found = false;
	for (i = 0; i < rentry->num_keys; i++)
	{
		if (pgsp_match_fn(key, &(rkeys[i]), 0) == 0)
		{
			found = true;
			break;
		}
	}

	if (!found)
		rkeys[rentry->num_keys++] = *key;

	dshash_release_lock(pgsp_rdepend, rentry);

	return true;
}

/*
 * Remove a reverse dependency for a (dbid, relid) on the given pgspEntry,
 * indentified by its key.
 */
void
pgsp_entry_unregister_rdepend(Oid dbid, Oid relid, pgspHashKey *key)
{
	pgspRdependEntry   *rentry;
	pgspHashKey			*rkeys;
	pgspRdependKey		rkey = {dbid, relid};
	int					delidx;

	Assert(LWLockHeldByMeInMode(pgsp->lock, LW_EXCLUSIVE));
	Assert(area != NULL);

	rentry = dshash_find(pgsp_rdepend, &rkey, true);

	if(!rentry)
		return;

	Assert(rentry->keys != InvalidDsaPointer);

	rkeys = (pgspHashKey *) dsa_get_address(area, rentry->keys);
	for(delidx = 0; delidx < rentry->num_keys; delidx++)
	{
		if (pgsp_match_fn(key, &(rkeys[delidx]), 0) == 0)
		{
			int pos;

			for (pos = delidx + 1; pos < rentry->num_keys; pos++)
				rkeys[pos - 1] = rkeys[pos];

			rentry->num_keys--;

			/* We should not register duplicated rdpend entries. */
			break;
		}
	}

	dshash_release_lock(pgsp_rdepend, rentry);
}

/* Calculate a hash value for a given key. */
uint32
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
int
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

/* Compare two rdepend keys.  Zero means match. */
int
pgsp_rdepend_fn_compare(const void *a, const void *b, size_t size,
								   void *arg)
{
	pgspRdependKey *k1 = (pgspRdependKey *) a;
	pgspRdependKey *k2 = (pgspRdependKey *) b;

	if (k1->dbid == k2->dbid && k1->relid == k2->relid)
		return 0;
	else
		return 1;
}

/* Calculate a hash value for a given rdepend key. */
dshash_hash
pgsp_rdepend_fn_hash(const void *v, size_t size, void *arg)
{
	pgspRdependKey *k = (pgspRdependKey *) v;
	uint32			h;

	h = hash_combine(0, k->dbid);
	h = hash_combine(h, k->relid);

	return h;
}
