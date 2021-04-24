-------------------------------
-- Test some general gotchas --
-------------------------------

--
-- Const detection
--
SET pg_shared_plans.min_plan_time = '0ms';
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
SELECT rolname, bypass, num_custom_plans, array_upper(relations, 1) AS nb_rels,
    constid != 0 AS has_constid, numconst,
    plantime > 0 AS has_plantime, size != '0 bytes' AS has_size,
    generic_cost > 0 AS has_generic_cost, substr(plan, 1, 50) AS plan_extract
FROM public.pg_shared_plans_all pgsp
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
SELECT rolname, bypass, num_custom_plans, array_upper(relations, 1) AS nb_rels,
    constid != 0 AS has_constid, numconst,
    plantime > 0 AS has_plantime, size != '0 bytes' AS has_size,
    generic_cost > 0 AS has_generic_cost, substr(plan, 1, 50) AS plan_extract
FROM public.pg_shared_plans_all pgsp
WHERE query LIKE '%another%';

--
-- RLS
--
SET pg_shared_plans.min_plan_time = '0ms';
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

-- Make sure plancache won't kick in
SET plan_cache_mode TO force_custom_plan;
SET role regress_c;
EXECUTE rls(10);
EXECUTE rls(10);
SET role regress_a;
EXECUTE rls(10);
EXECUTE rls(10);
SET role regress_b;
EXECUTE rls(10);
EXECUTE rls(10);
SET plan_cache_mode TO auto;

RESET role;
SELECT rolname, bypass, num_custom_plans, array_upper(relations, 1) AS nb_rels,
    plantime > 0 AS has_plantime, size != '0 bytes' AS has_size,
    generic_cost > 0 AS has_generic_cost, substr(plan, 1, 50) AS plan_extract
FROM public.pg_shared_plans_all pgsp
WHERE query LIKE '%mysecretdata%'
ORDER BY rolname COLLATE "C" ASC;

-- test rdepend filtering
SELECT 'mysecretdata'::regclass::oid AS mysecretdataoid \gset

SELECT rolname
FROM pg_shared_plans(false, false, 0, :mysecretdataoid) pgsp
LEFT JOIN pg_roles r ON r.oid = pgsp.userid
ORDER BY rolname COLLATE "C" ASC;

-- test partial reset, and rdepend unregister
SELECT pg_shared_plans_reset('regress_a'::regrole);

SELECT rolname
FROM pg_shared_plans(false, false, 0, :mysecretdataoid) pgsp
LEFT JOIN pg_roles r ON r.oid = pgsp.userid
ORDER BY rolname COLLATE "C" ASC;

-- Should remove all dependent plans
DROP TABLE mysecretdata CASCADE;

SELECT rolname
FROM pg_shared_plans(false, false, 0, :mysecretdataoid) pgsp
LEFT JOIN pg_roles r ON r.oid = pgsp.userid
ORDER BY rolname COLLATE "C" ASC;

CREATE VIEW myview AS SELECT generate_series(1, 2) id;
PREPARE myview(integer) AS SELECT * FROM myview WHERE id = $1;

EXECUTE myview(1);
EXECUTE myview(1);

-- Should find a saved plan, with 1 bypass
SELECT bypass, array_upper(relations, 1) AS nb_rels
FROM public.pg_shared_plans_all pgsp
WHERE query LIKE '%myview%';

-- Should remove all dependent plans
DROP VIEW myview;
SELECT bypass, array_upper(relations, 1) AS nb_rels
FROM public.pg_shared_plans_all pgsp
WHERE query LIKE '%myview%';

--
-- temp table
--
CREATE TEMPORARY TABLE mytemp(id integer);
PREPARE mytemp(int) AS SELECT * FROM mytemp WHERE id = $1;

-- Should not add the query in shared cache
EXECUTE mytemp(1);

-- Should not find any entry
SELECT rolname, bypass, num_custom_plans, array_upper(relations, 1) AS nb_rels,
    plantime > 0 AS has_plantime, size != '0 bytes' AS has_size,
    generic_cost > 0 AS has_generic_cost, substr(plan, 1, 50) AS plan_extract
FROM public.pg_shared_plans_all pgsp
WHERE query LIKE '%mytemp%'
ORDER BY rolname COLLATE "C" ASC;

--
-- ACL on functions
--
PREPARE cast_bigint(int) AS SELECT (ARRAY [$1])::int4[]::bigint[];
BEGIN;
EXECUTE cast_bigint(1);
EXECUTE cast_bigint(1);
REVOKE ALL ON FUNCTION int8(integer) FROM PUBLIC;
EXECUTE cast_bigint(1); -- superuser, succeed
SET SESSION AUTHORIZATION regress_a;
EXECUTE cast_bigint(1); -- other user, fail
ROLLBACK;

--
-- Rules
--
CREATE TABLE rule_1(id integer, val text);
CREATE TABLE rule_2(id integer, val text);
CREATE TABLE rule_3(id integer, val text);
INSERT INTO rule_1 VALUES (1, 'val 1');
INSERT INTO rule_2 VALUES (1, 'val 1');
INSERT INTO rule_3 VALUES (1, 'val 1');

PREPARE upd_rule_1(int, text) AS UPDATE rule_1 SET val = $2 WHERE id = $1;

-- without rule, we will cache a plan and then bypass the planner
EXECUTE upd_rule_1(0, 'noop');
EXECUTE upd_rule_1(0, 'noop');

SELECT bypass FROM pg_shared_plans WHERE query LIKE '%rule_1%';

CREATE RULE rule_test AS ON UPDATE TO rule_1 DO ALSO (
    UPDATE rule_2 SET val = new.val WHERE val = old.val;
    UPDATE rule_3 SET val = new.val WHERE val = old.val;
);

-- now that we have a rule, we shouldn't use the saved plan anymore
EXECUTE upd_rule_1(1, 'new val');

SELECT bypass FROM pg_shared_plans WHERE query LIKE '%rule_1%';

SELECT * FROM rule_1;
SELECT * FROM rule_2;
SELECT * FROM rule_3;

--
-- Grouping Sets
--
PREPARE rollup_1(int) AS SELECT (
    SELECT (
        SELECT GROUPING(a,b) FROM (VALUES ($1)) v2(c)
    ) FROM (VALUES (1,2)) v1(a,b) GROUP BY (a,b)
) FROM (VALUES(6,7)) v3(e,f) GROUP BY ROLLUP(e,f);

-- pg_stat_statements will generate the same queryid for this query, make sure
-- we see it as a different one
PREPARE rollup_2(int) AS SELECT (
    SELECT (
        SELECT GROUPING(e,f) FROM (VALUES ($1)) v2(c)
    ) FROM (VALUES (1,2)) v1(a,b) GROUP BY (a,b)
) FROM (VALUES(6,7)) v3(e,f) GROUP BY ROLLUP(e,f);

EXECUTE rollup_1(1);
EXECUTE rollup_1(1);

EXECUTE rollup_2(1);
EXECUTE rollup_2(1);

-- We should see 2 entries, each having bypassed the planner once
SELECT bypass FROM pg_shared_plans WHERE query LIKE '%v1(a,b)%';

PREPARE groupby_1(int) AS SELECT a, b, c
 FROM (VALUES ($1, 2, 3), (4, NULL, 6), (7, 8, 9)) AS t (a, b, c)
 GROUP BY ROLLUP(a, b), rollup(a, c)
 ORDER BY a, b, c;

-- pg_stat_statements will generate the same queryid for this query, make sure
-- we see it as a different one
PREPARE groupby_2(int) AS SELECT a, b, c
 FROM (VALUES ($1, 2, 3), (4, NULL, 6), (7, 8, 9)) AS t (a, b, c)
 GROUP BY DISTINCT ROLLUP(a, b), rollup(a, c)
 ORDER BY a, b, c;

EXECUTE groupby_1(1);
EXECUTE groupby_1(1);

EXECUTE groupby_2(1);
EXECUTE groupby_2(1);

-- We should see 2 entries, each having bypassed the planner once
SELECT bypass FROM pg_shared_plans WHERE query LIKE '%SELECT a, b, c%';

--
-- Limit option
--
CREATE TABLE limitoption AS SELECT 0 AS val FROM generate_series(1, 10);
PREPARE limitoption_1(int) AS SELECT *
    FROM limitoption
    WHERE val < $1
    ORDER BY val
    FETCH FIRST 2 ROWS WITH TIES;
-- pg_stat_statements will generate the same queryid for this query, make sure
-- we see it as a different one
PREPARE limitoption_2(int) AS SELECT *
    FROM limitoption
    WHERE val < $1
    ORDER BY val
    FETCH FIRST 2 ROW ONLY;

EXECUTE limitoption_1(5);
EXECUTE limitoption_1(5);
EXECUTE limitoption_2(5);
EXECUTE limitoption_2(5);

-- We should see 2 entries, each having bypassed the planner once
SELECT bypass FROM pg_shared_plans WHERE query LIKE '%limitoption%';

--
-- alias' colnames
--
CREATE TABLE colname AS SELECT 0 AS id, 'zero' AS val;
PREPARE colname_1(int) AS SELECT row_to_json(t) FROM colname t WHERE id = $1;
-- pg_stat_statements will generate the same queryid for this query, make sure
-- we see it as a different one
PREPARE colname_2(int) AS SELECT row_to_json(t) FROM colname t(a, b) WHERE a = $1;

EXECUTE colname_1(0);
EXECUTE colname_1(0);
EXECUTE colname_2(0);
EXECUTE colname_2(0);

-- We should see 2 entries, each having bypassed the planner once
SELECT bypass FROM pg_shared_plans WHERE query LIKE '%row_to_json%';

PREPARE colname_3(int) AS SELECT row_to_json(colname_bis)
    FROM (SELECT id, val FROM colname) AS colname_bis;
-- pg_stat_statements will generate the same queryid for this query, make sure
-- we see it as a different one
PREPARE colname_4(int) AS SELECT row_to_json(colname_bis)
    FROM (SELECT id AS a, val AS b FROM colname) AS colname_bis;

EXECUTE colname_3(0);
EXECUTE colname_3(0);
EXECUTE colname_4(0);
EXECUTE colname_4(0);

-- We should see 2 entries, each having bypassed the planner once
SELECT bypass FROM pg_shared_plans WHERE query LIKE '%colname_bis%';

--
-- TEXT SEARCH DICTIONARY
--
CREATE TEXT SEARCH DICTIONARY synonym (
						Template=synonym,
						Synonyms=synonym_sample
);

PREPARE ts_lexize(text) AS SELECT ts_lexize('synonym', $1);

EXECUTE ts_lexize('PoStGrEs');
EXECUTE ts_lexize('PoStGrEs');
-- plan should be cached and bypassed planner once
SELECT bypass FROM pg_shared_plans WHERE query LIKE '%ts_lexize%';
-- Should evict all plans for current database
ALTER TEXT SEARCH DICTIONARY synonym (CaseSensitive = 1);
-- Note that this statement will not fail as the current backend will receive
-- an invalidation for the dictionnary, but there's no guarantee that other
-- backends will.
EXECUTE ts_lexize('PoStGrEs');

-- We should see only 1 entry for the current database, which never bypassed
-- the planner
SELECT bypass FROM pg_shared_plans WHERE datname = current_database();

--
-- custom types
--
CREATE TYPE comptype AS (r float8, i float8);
CREATE DOMAIN dcomptype AS comptype;
CREATE TABLE dcomptable (d1 dcomptype unique);

INSERT INTO dcomptable VALUES (row(1,2)::dcomptype);
INSERT INTO dcomptable VALUES (row(3,4)::comptype);
INSERT INTO dcomptable (d1.r) VALUES (11);

PREPARE dcomptable(int) AS UPDATE dcomptable SET d1.r = (d1).r + $1 WHERE (d1).i > 0;

EXECUTE dcomptable(0);
EXECUTE dcomptable(1);

-- plan should be cached and bypassed planner once
SELECT bypass FROM pg_shared_plans WHERE query LIKE '%dcomptable%';

-- Should discard the plan
ALTER DOMAIN dcomptype ADD CONSTRAINT c1 CHECK ((value).r <= (value).i);
SELECT bypass, discard FROM pg_shared_plans WHERE query LIKE '%dcomptable%';

-- Should fail
EXECUTE dcomptable(1);

CREATE TABLE domtab (col1 integer, col2 integer);
CREATE DOMAIN dom AS integer;
CREATE VIEW domview AS SELECT cast(col1 AS dom), col2 from domtab;
INSERT INTO domtab (col1, col2) VALUES (NULL, 1);
INSERT INTO domtab (col1, col2) VALUES (5, 1);

PREPARE domview(int) AS SELECT * FROM domview WHERE col2 = $1 ORDER BY col1;

EXECUTE domview(1);
EXECUTE domview(1);

-- plan should be cached and bypassed planner once
SELECT bypass FROM pg_shared_plans WHERE query LIKE '%domview%';

-- Should discard the plan
ALTER DOMAIN dom SET NOT NULL;
SELECT bypass, discard FROM pg_shared_plans WHERE query LIKE '%domview%';

-- Should fail
EXECUTE domview(1);

CREATE DOMAIN di AS int;
CREATE FUNCTION dom_check(int) RETURNS di AS $$
DECLARE d di;
BEGIN
  d := $1::di;
  RETURN d;
END
$$ LANGUAGE PLPGSQL IMMUTABLE;

PREPARE dom_check(int) AS SELECT dom_check($1);

EXECUTE dom_check(0);
EXECUTE dom_check(0);

-- plan should be cached and bypassed planner once
SELECT bypass FROM pg_shared_plans WHERE query LIKE '%dom_check%';

-- Should not discard the plan
ALTER DOMAIN di ADD CONSTRAINT pos CHECK (value > 0);
SELECT bypass, discard FROM pg_shared_plans WHERE query LIKE '%dom_check%';

-- Should fail
EXECUTE dom_check(0);

-- implicit cast during assigment is a separate code path, test that too
ALTER DOMAIN di DROP CONSTRAINT pos;
EXECUTE dom_check(0);

-- Should discard the plan
CREATE OR REPLACE FUNCTION dom_check(int) RETURNS di AS $$
DECLARE d di;
BEGIN
  d := $1;
  RETURN d;
END
$$ LANGUAGE PLPGSQL IMMUTABLE;

EXECUTE dom_check(0);
SELECT bypass, discard FROM pg_shared_plans WHERE query LIKE '%dom_check%';

ALTER DOMAIN di ADD CONSTRAINT pos CHECK (value > 0);
SELECT bypass, discard FROM pg_shared_plans WHERE query LIKE '%dom_check%';

-- Should fail
EXECUTE dom_check(0);

SELECT bypass, discard FROM pg_shared_plans WHERE query LIKE '%dom_check%';

--
-- dependencies on functions
--
CREATE TYPE myfunc_type AS (f1 integer, f2 integer);
CREATE FUNCTION myfunc() RETURNS myfunc_type AS $$
  SELECT 1, 2;
$$ LANGUAGE sql IMMUTABLE;

PREPARE myfunc(integer) AS SELECT myfunc() WHERE 1 != $1;

EXECUTE myfunc(0);
EXECUTE myfunc(0);

-- plan should be cached and bypassed planner once
SELECT bypass FROM pg_shared_plans WHERE query LIKE '%myfunc%';

-- should discard the plan
CREATE OR REPLACE FUNCTION myfunc() RETURNS myfunc_type AS $$
  SELECT 3, 4;
$$ LANGUAGE sql VOLATILE;
SELECT bypass, discard FROM pg_shared_plans WHERE query LIKE '%myfunc%';

EXECUTE myfunc(0);

-- should discard the plan
ALTER FUNCTION myfunc() STABLE;
SELECT bypass, discard FROM pg_shared_plans WHERE query LIKE '%myfunc%';

-- should evict the entry
DROP FUNCTION myfunc();

SELECT count(*) FROM pg_shared_plans WHERE query LIKE '%myfunc%';
