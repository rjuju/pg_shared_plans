SELECT pg_shared_plans_reset();

--
-- Test plancache override
--
SET plan_cache_mode TO auto;
SET pg_shared_plans.enabled = off;
CREATE TABLE plancache AS SELECT 1 AS id, 'val' AS text;
PREPARE plancache(int) AS SELECT * FROM plancache WHERE id = $1;

EXECUTE plancache(1);
EXECUTE plancache(1);
EXECUTE plancache(1);
EXECUTE plancache(1);
EXECUTE plancache(1);
-- should be a (plancache) generic plan
EXPLAIN (COSTS OFF) EXECUTE plancache(1);

SET pg_shared_plans.enabled = on;
SET pg_shared_plans.min_plan_time = '0ms';
SET pg_shared_plans.threshold = 4;
PREPARE plancache2(int) AS SELECT * FROM plancache WHERE id = $1;
EXECUTE plancache2(1);
EXECUTE plancache2(1);
EXECUTE plancache2(1);
EXECUTE plancache2(1);
-- should bypass the planner
EXECUTE plancache2(1);
-- should bypass the planner and not create a plancache entry
EXECUTE plancache2(1);
SELECT rolname, bypass, num_custom_plans, array_upper(relations, 1) AS nb_rels,
    plantime > 0 AS has_plantime, size != '0 bytes' AS has_size,
    generic_cost > 0 AS has_generic_cost, substr(plan, 1, 50) AS plan_extract
FROM public.pg_shared_plans_all pgsp
WHERE query LIKE '%plancache%';

SET pg_shared_plans.enabled = off;
-- should now be a custom plan
EXPLAIN (COSTS OFF) EXECUTE plancache2(1);

-- Test all SRFs
SELECT count(*) FROM pg_shared_plans(false, false);
SELECT count(*) FROM pg_shared_plans(false, true);
SELECT count(*) FROM pg_shared_plans(true, false);
SELECT count(*) FROM pg_shared_plans(true, true);
--
-- Test general behavior with planning time threshold
--
SET join_collapse_limit = 12;
SET geqo_threshold = 20;
SET plan_cache_mode = force_custom_plan;
SET pg_shared_plans.enabled = on;
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
SELECT rolname, bypass, num_custom_plans, array_upper(relations, 1) AS nb_rels,
    plantime > 0 AS has_plantime, size != '0 bytes' AS has_size,
    generic_cost > 0 AS has_generic_cost, substr(plan, 1, 50) AS plan_extract
FROM public.pg_shared_plans_all pgsp
WHERE query LIKE '%pg_class c%';

-- should not be cached as planning time should be too fast
EXECUTE fast(1);
EXECUTE fast(1);

SELECT rolname, bypass, num_custom_plans, array_upper(relations, 1) AS nb_rels,
    plantime > 0 AS has_plantime, size != '0 bytes' AS has_size,
    generic_cost > 0 AS has_generic_cost, substr(plan, 1, 50) AS plan_extract
FROM public.pg_shared_plans_all pgsp
WHERE query LIKE '%+%';

-- Test correct behavior when there are no source relation */
SET pg_shared_plans.min_plan_time = '0ms';
EXECUTE fast(1);
EXECUTE fast(1);
SELECT rolname, bypass, num_custom_plans, array_upper(relations, 1) AS nb_rels,
    plantime > 0 AS has_plantime, size != '0 bytes' AS has_size,
    generic_cost > 0 AS has_generic_cost, substr(plan, 1, 50) AS plan_extract
FROM public.pg_shared_plans_all pgsp
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

SET pg_shared_plans.min_plan_time = '0ms';
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
SELECT rolname, bypass, num_custom_plans, array_upper(relations, 1) AS nb_rels,
    plantime > 0 AS has_plantime, size != '0 bytes' AS has_size,
    generic_cost > 0 AS has_generic_cost, substr(plan, 1, 50) AS plan_extract
FROM public.pg_shared_plans_all pgsp
WHERE query LIKE '%mytable%';
