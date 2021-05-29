-- test nested call of pg_shared_plans()
SELECT pg_shared_plans_reset(coalesce(userid, 0), dbid, queryid)
FROM pg_shared_plans()
LIMIT 1;
