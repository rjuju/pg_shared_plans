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

#include "catalog/pg_class_d.h"
#include "catalog/pg_type.h"
#include "commands/dbcommands.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"
#if PG_VERSION_NUM >= 130000
#include "common/hashfn.h"
#else
#include "utils/hashutils.h"
#endif
#include "tcop/utility.h"
#include "utils/lsyscache.h"
#include "utils/syscache.h"

#include "include/pgsp_rdepend.h"

#define RDEPEND_KEY_SIZE(nb)	(sizeof(pgspHashKey) * (nb))

int pgsp_rdepend_max;

static void pgsp_get_rdep_name(Oid classid, Oid oid, char **deptype,
		char **depname);

/*
 * Add a reverse depdency for a (dbid, classid, oid) on the given pgspEntry,
 * identified by its key.
 */
bool
pgsp_entry_register_rdepend(Oid dbid, Oid classid, Oid oid, pgspHashKey *key)
{
	pgspRdependKey rkey = {dbid, classid, oid};
	pgspRdependEntry   *rentry;
	pgspHashKey			*rkeys;
	bool				found, dsfound;
	int					i;

	/* Note that even though we hold an exlusive lock on pgsp->lock, it will
	 * eventually be released before the related entry is inserted in the main
	 * hash table.
	 */
	Assert(LWLockHeldByMeInMode(pgsp->lock, LW_EXCLUSIVE));
	Assert(pgsp_area != NULL && pgsp_rdepend != NULL);

	if (classid != RELOID && classid != TYPEOID && classid != PROCOID)
		elog(ERROR, "pgsp: rdepend classid %d not handled", classid);

	rentry = dshash_find_or_insert(pgsp_rdepend, &rkey, &dsfound);

	if (!dsfound)
	{
		volatile pgspSharedState *s = (volatile pgspSharedState *) pgsp;

		rentry->max_keys = PGSP_RDEPEND_INIT;
		rentry->num_keys = 0;
		rentry->keys = dsa_allocate_extended(pgsp_area,
				RDEPEND_KEY_SIZE(PGSP_RDEPEND_INIT),
				DSA_ALLOC_NO_OOM);

		if (rentry->keys == InvalidDsaPointer)
		{
			dshash_delete_entry(pgsp_rdepend, rentry);

			return false;
		}

		SpinLockAcquire(&s->mutex);
		s->rdepend_num++;
		s->alloced_size += RDEPEND_KEY_SIZE(PGSP_RDEPEND_INIT);
		SpinLockRelease(&s->mutex);
	}
	Assert(rentry->keys != InvalidDsaPointer);

	if (rentry->num_keys >= rentry->max_keys)
	{
		dsa_pointer new_rkeys_p;
		pgspHashKey *new_rkeys;
		int new_max_keys = Max(rentry->max_keys * 2, pgsp_rdepend_max);
		volatile pgspSharedState *s = (volatile pgspSharedState *) pgsp;

		SpinLockAcquire(&s->mutex);
		Assert(s->alloced_size >= RDEPEND_KEY_SIZE(rentry->max_keys));
		SpinLockRelease(&s->mutex);

		Assert(dsfound);

		/*
		 * Too many rdepend entries for this object, refuse to create a new
		 * pgspEntry and raise a WARNING.
		 */
		if (rentry->num_keys >= pgsp_rdepend_max)
		{
			char *deptype;
			char *depname;

			pgsp_get_rdep_name(classid, oid, &deptype, &depname);

			ereport(WARNING,
					(errmsg("pgsp: Too many cache entries for %s \"%s\""
					" on database \"%s\"",
					deptype, depname, get_database_name(dbid))),
					errhint("You might want to increase"
						" pg_shared_plans.rdepend_max"));

			dshash_release_lock(pgsp_rdepend, rentry);
			return false;
		}

		rkeys = (pgspHashKey *) dsa_get_address(pgsp_area, rentry->keys);
		Assert(rkeys != NULL);

		/*
		 * The area is pinned, so we can't process an interrupt here as we
		 * could otherwise leak memory permanently.
		 */
		HOLD_INTERRUPTS();
		new_rkeys_p = dsa_allocate_extended(pgsp_area,
											sizeof(pgspHashKey) * new_max_keys,
											DSA_ALLOC_NO_OOM);
		if (new_rkeys_p == InvalidDsaPointer)
		{
			char *deptype;
			char *depname;

			pgsp_get_rdep_name(classid, oid, &deptype, &depname);

			elog(WARNING, "pgsp: Could not cache entries for %s \"%s\""
					" on database \"%s\": out of shared memory",
					deptype, depname, get_database_name(dbid));

			dshash_release_lock(pgsp_rdepend, rentry);
			RESUME_INTERRUPTS();
			return false;
		}

		new_rkeys = (pgspHashKey *) dsa_get_address(pgsp_area, new_rkeys_p);
		Assert(new_rkeys != NULL);

		memcpy(new_rkeys, rkeys, sizeof(pgspHashKey) * new_max_keys);
		rkeys = NULL;
		dsa_free(pgsp_area, rentry->keys);

		SpinLockAcquire(&s->mutex);
		s->alloced_size += RDEPEND_KEY_SIZE(new_max_keys - rentry->max_keys);
		SpinLockRelease(&s->mutex);

		rentry->keys = new_rkeys_p;
		rentry->max_keys = new_max_keys;

		RESUME_INTERRUPTS();
	}

	rkeys = (pgspHashKey *) dsa_get_address(pgsp_area, rentry->keys);
	Assert(rkeys != NULL);

	/* Check first if the rdepend is already registered */
	found = false;
	for (i = 0; i < rentry->num_keys; i++)
	{
		if (pgsp_match_fn(key, &(rkeys[i]), 0) == 0)
		{
			found = true;
#if defined(USE_ASSERT_CHECKING)
			continue;
#else
			break;
#endif
		}
#if defined(USE_ASSERT_CHECKING)
		Assert(pgsp_match_fn(key, &(rkeys[i]), 0) != 0);
#endif
	}

	if (!found)
		rkeys[rentry->num_keys++] = *key;
	else
	{
		Assert(dsfound);
	}

	/* Just extra safety check. */
	if(!dsfound)
	{
		Assert(!found);
	}

	dshash_release_lock(pgsp_rdepend, rentry);

	return true;
}

/*
 * Remove a reverse dependency for a (dbid, classid, oid) on the given pgspEntry,
 * indentified by its key.
 */
void
pgsp_entry_unregister_rdepend(Oid dbid, Oid classid, Oid oid, pgspHashKey *key)
{
	pgspRdependEntry   *rentry;
	pgspHashKey			*rkeys;
	pgspRdependKey		rkey = {dbid, classid, oid};
	int					delidx;

	Assert(LWLockHeldByMeInMode(pgsp->lock, LW_EXCLUSIVE));
	Assert(pgsp_area != NULL);

	if (classid != RELOID && classid != TYPEOID && classid != PROCOID)
		elog(ERROR, "pgsp: rdepend classid %d not handled", classid);

	rentry = dshash_find(pgsp_rdepend, &rkey, true);

	if(!rentry)
		return;

	Assert(rentry->keys != InvalidDsaPointer);

	/* We might end up removing the rdepend entry, so we can't process
	 * interrupts here as we could otherwise permanently leak memory
	 * permanently.
	 */
	HOLD_INTERRUPTS();

	rkeys = (pgspHashKey *) dsa_get_address(pgsp_area, rentry->keys);
	for(delidx = 0; delidx < rentry->num_keys; delidx++)
	{
		if (pgsp_match_fn(key, &(rkeys[delidx]), 0) == 0)
		{
			int pos;

			for (pos = delidx + 1; pos < rentry->num_keys; pos++)
				rkeys[pos - 1] = rkeys[pos];

			Assert(rentry->num_keys > 0);
			rentry->num_keys--;

#if defined(USE_ASSERT_CHECKING)
			continue;
#else
			/* We should not register duplicated rdpend entries. */
			break;
#endif
		}
#if defined(USE_ASSERT_CHECKING)
		Assert(pgsp_match_fn(key, &(rkeys[delidx]), 0) != 0);
#endif
	}

	if (rentry->num_keys == 0)
	{
		volatile pgspSharedState *s = (volatile pgspSharedState *) pgsp;

		dsa_free(pgsp_area, rentry->keys);

		SpinLockAcquire(&s->mutex);
		Assert(s->alloced_size >= RDEPEND_KEY_SIZE(rentry->max_keys));
		s->alloced_size -= RDEPEND_KEY_SIZE(rentry->max_keys);
		s->rdepend_num--;
		SpinLockRelease(&s->mutex);

		rentry->keys = InvalidDsaPointer;
		dshash_delete_entry(pgsp_rdepend, rentry);
	}
	else
		dshash_release_lock(pgsp_rdepend, rentry);

	RESUME_INTERRUPTS();
}

static void
pgsp_get_rdep_name(Oid classid, Oid oid, char **deptype, char **depname)
{
	if (classid == RELOID)
	{
		*depname = get_rel_name(oid);
		*deptype = "relation";
	}
	else if (classid == TYPEOID)
	{
		HeapTuple tp;

		tp = SearchSysCache1(TYPEOID, ObjectIdGetDatum(oid));
		if (HeapTupleIsValid(tp))
		{
			Form_pg_type typtup = (Form_pg_type) GETSTRUCT(tp);
			*depname = pstrdup(typtup->typname.data);
			ReleaseSysCache(tp);
		}
		else
			*depname = "<unknown>";
		*deptype = "type";
	}
	else if (classid == PROCOID)
	{
		*depname = get_func_name(oid);
		if (!*depname)
			*depname = "<unknown";
		*deptype = "routine";
	}
	else
	{
		/* Should not happen. */
		elog(ERROR, "pgsp: rdepend classid %d not handled", classid);
	}
}

/* Compare two rdepend keys.  Zero means match. */
int
pgsp_rdepend_fn_compare(const void *a, const void *b, size_t size,
								   void *arg)
{
	pgspRdependKey *k1 = (pgspRdependKey *) a;
	pgspRdependKey *k2 = (pgspRdependKey *) b;

	if (k1->dbid == k2->dbid && k1->classid == k2->classid && k1->oid == k2->oid)
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
	h = hash_combine(h, k->classid);
	h = hash_combine(h, k->oid);

	return h;
}
