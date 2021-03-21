SET join_collapse_limit = 12;
SET geqo_threshold = 20;
SET plan_cache_mode = force_custom_plan;

CREATE EXTENSION pg_stat_statements WITH SCHEMA public;
CREATE EXTENSION pg_shared_plans WITH SCHEMA public;

SELECT pg_shared_plans_reset();

SET pg_shared_plans.enabled = on;

--
-- Test general behavior with planning time threshold
--
SET pg_shared_plans.threshold = 1;
SET pg_shared_plans.min_plan_time = '50ms';

PREPARE slow1(oid) AS
    SELECT count(*) FROM pg_class c JOIN pg_class c1 USING (oid)
    JOIN pg_class c2 USING (oid) JOIN pg_class c3 USING (oid)
    JOIN pg_class c4 USING (oid) JOIN pg_class c5 USING (oid)
    JOIN pg_class c7 USING (oid) JOIN pg_class c8 USING (oid)
    JOIN pg_class c9 USING (oid) JOIN pg_class c10 USING (oid)
    JOIN pg_class c11 USING (oid) JOIN pg_class c12 USING (oid)
    WHERE c.oid = $1;

PREPARE slow2(oid) AS
    SELECT count(*) FROM pg_class c JOIN pg_class c1 USING (oid)
    JOIN pg_class c2 USING (oid) JOIN pg_class c3 USING (oid)
    JOIN pg_class c4 USING (oid) JOIN pg_class c5 USING (oid)
    JOIN pg_class c7 USING (oid) JOIN pg_class c8 USING (oid)
    JOIN pg_class c9 USING (oid) JOIN pg_class c10 USING (oid)
    JOIN pg_class c11 USING (oid) JOIN pg_class c12 USING (oid)
    WHERE c.oid = $1;

PREPARE fast(int) AS
    SELECT $1 + $1 AS fast;

-- Should add the query in shared cache
EXECUTE slow1('pg_class'::regclass);
-- Should bypass the planner
EXECUTE slow1('pg_class'::regclass);
-- Should bypass planner as the queryid should be identical
EXECUTE slow2('pg_class'::regclass);
-- Should bypass planner as the queryid should be identical, and return a
-- correct result
EXECUTE slow1(0);
-- Should bypass planner as the queryid should be identical, and return a
-- correct result
EXECUTE slow2(0);

-- Check that the plan is saved, planned once, used 4 times, with no dependency
-- on role
SELECT rolname, bypass, num_custom_plans,
    plantime > 0 AS has_plantime, size != '0 bytes' AS has_size,
    generic_cost > 0 AS has_generic_cost, substr(plan, 1, 50) AS plan_extract
FROM public.pg_shared_plans_detailed pgsp
WHERE query LIKE '%pg_class c%';

-- should not be cached as planning time should be too fast
execute fast(1);
execute fast(1);

SELECT rolname, bypass, num_custom_plans,
    plantime > 0 AS has_plantime, size != '0 bytes' AS has_size,
    generic_cost > 0 AS has_generic_cost, substr(plan, 1, 50) AS plan_extract
FROM public.pg_shared_plans_detailed pgsp
WHERE query LIKE '%+%';

--
-- Test correct behavior with search_path changes
--
CREATE SCHEMA s1;
CREATE TABLE s1.mytable AS SELECT 1 AS id, 'ns1' AS val;
CREATE SCHEMA s2;
CREATE TABLE s2.mytable AS SELECT 1 AS id, 'ns2' AS val;

SET search_path TO s1;
PREPARE ns (int) AS SELECT val FROM mytable WHERE id = $1;

set pg_shared_plans.min_plan_time = '0ms';
-- Should add the query in shared cache
EXECUTE ns(1);
-- Should bypass the planner
EXECUTE ns(1);
SET search_path TO s2;
-- Should NOT bypass the planner and add the query in shared cache
EXECUTE ns(1);
-- Should bypass the planner
EXECUTE ns(1);

-- should find two identical rows for the two added plans, each planed and
-- bypassed once, without dependency on role
SELECT rolname, bypass, num_custom_plans,
    plantime > 0 AS has_plantime, size != '0 bytes' AS has_size,
    generic_cost > 0 AS has_generic_cost, substr(plan, 1, 50) AS plan_extract
FROM public.pg_shared_plans_detailed pgsp
WHERE query LIKE '%mytable%';

--------------------------------------------
-- and test the known handled limitations --
--------------------------------------------

--
-- Const detection
--
set pg_shared_plans.min_plan_time = '0ms';
SET search_path TO public;
CREATE TABLE small AS SELECT 1 AS id FROM generate_series(1, 10);

PREPARE limit_a(int) AS SELECT id FROM small WHERE id = $1 LIMIT 1;
PREPARE limit_b(int) AS SELECT id FROM small WHERE id = $1 LIMIT 2;

-- Should add the query in shared cache and then bypass planner
EXECUTE limit_a(1);
EXECUTE limit_a(1);
-- Should add the query in shared cache and then bypass planner
EXECUTE limit_b(1);
EXECUTE limit_b(1);

-- Should find two entries, queries containing const values
SELECT rolname, bypass, num_custom_plans,
    constid != 0 AS has_constid, numconst,
    plantime > 0 AS has_plantime, size != '0 bytes' AS has_size,
    generic_cost > 0 AS has_generic_cost, substr(plan, 1, 50) AS plan_extract
FROM public.pg_shared_plans_detailed pgsp
WHERE query LIKE '%small%';

CREATE TABLE another AS SELECT 1 AS id, 'val' AS val;
PREPARE where_a(int) AS WITH src AS (SELECT 0 UNION ALL SELECT * FROM (SELECT id FROM another WHERE id = 1) s) SELECT COUNT(*) FROM src;
PREPARE where_b(int) AS WITH src AS (SELECT 0 UNION ALL SELECT * FROM (SELECT id FROM another WHERE id = 0) s) SELECT COUNT(*) FROM src;

-- Should add the query in shared cache and then bypass planner
EXECUTE where_a(1);
EXECUTE where_a(1);
-- Should add the query in shared cache and then bypass planner
EXECUTE where_b(1);
EXECUTE where_b(1);
-- Should find two entries, queries containing const values
SELECT rolname, bypass, num_custom_plans,
    constid != 0 AS has_constid, numconst,
    plantime > 0 AS has_plantime, size != '0 bytes' AS has_size,
    generic_cost > 0 AS has_generic_cost, substr(plan, 1, 50) AS plan_extract
FROM public.pg_shared_plans_detailed pgsp
WHERE query LIKE '%another%';

--
-- RLS
--
set pg_shared_plans.min_plan_time = '0ms';
SET search_path TO public;
CREATE USER regress_a;
CREATE USER regress_b;
CREATE USER regress_c BYPASSRLS;
CREATE TABLE mysecretdata(user_name text, secret text, val int);
GRANT SELECT ON mysecretdata TO public;
INSERT INTO mysecretdata VALUES ('regress_a', 'one', 1), ('regress_b', 'two', 2);
ALTER TABLE mysecretdata ENABLE ROW LEVEL SECURITY;
CREATE POLICY see_self ON mysecretdata FOR SELECT
    USING (current_user = user_name);

PREPARE rls (int) AS SELECT * FROM mysecretdata WHERE val < $1;

SET role regress_c;
EXECUTE rls(10);
EXECUTE rls(10);
SET role regress_a;
EXECUTE rls(10);
EXECUTE rls(10);
SET role regress_b;
EXECUTE rls(10);
EXECUTE rls(10);

RESET role;
SELECT rolname, bypass, num_custom_plans,
    plantime > 0 AS has_plantime, size != '0 bytes' AS has_size,
    generic_cost > 0 AS has_generic_cost, substr(plan, 1, 50) AS plan_extract
FROM public.pg_shared_plans_detailed pgsp
WHERE query LIKE '%mysecretdata%'
ORDER BY rolname COLLATE "C" ASC;

DROP TABLE mysecretdata CASCADE;
DROP ROLE regress_a;
DROP ROLE regress_b;
DROP ROLE regress_c;
