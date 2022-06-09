SET pg_shared_plans.threshold = 1;
SET pg_shared_plans.min_plan_time = 0;
SELECT pg_shared_plans_reset();

CREATE TABLE inh_a(id1 integer);
CREATE TABLE inh_b(id2 integer);

PREPARE inh_a(int) AS SELECT * FROM inh_a WHERE id1 = $1;
PREPARE inh_b(int) AS SELECT * FROM inh_b WHERE id2 = $1;

EXECUTE inh_a(1);
EXECUTE inh_a(1);
EXECUTE inh_b(1);
EXECUTE inh_b(1);

SELECT 't1' t, bypass, discard, query, relation
FROM ( SELECT *, unnest(relations)::regclass::text AS relation
       FROM pg_shared_plans_relations WHERE query LIKE '%inh%') s
ORDER BY query COLLATE "C", relation COLLATE "C", bypass, discard;

-- creating a table in an inheritance tree should discard entries depending on
-- any of the parent relations
CREATE TABLE inh_a_1() INHERITS (inh_a);

PREPARE inh_a_1(int) AS SELECT * FROM inh_a_1 WHERE id1 = $1;

-- we need to cache a new plan so it can later be discarded
EXECUTE inh_a(1);
EXECUTE inh_a_1(1);
EXECUTE inh_a_1(1);

SELECT 't2' t, bypass, discard, query, relation
FROM ( SELECT *, unnest(relations)::regclass::text AS relation
       FROM pg_shared_plans_relations WHERE query LIKE '%inh%') s
ORDER BY query COLLATE "C", relation COLLATE "C", bypass, discard;

CREATE TABLE inh_a_1_b() INHERITS (inh_a_1, inh_b);
PREPARE inh_a_1_b(int) AS SELECT * FROM inh_a_1_b WHERE id1 = $1;

-- we need to cache new plans so they can later be discarded
EXECUTE inh_a(1);
EXECUTE inh_b(1);
EXECUTE inh_a_1(1);
EXECUTE inh_a_1_b(1);
EXECUTE inh_a_1_b(1);

SELECT 't3' t, bypass, discard, query, relation
FROM ( SELECT *, unnest(relations)::regclass::text AS relation
       FROM pg_shared_plans_relations WHERE query LIKE '%inh%') s
ORDER BY query COLLATE "C", relation COLLATE "C", bypass, discard;

CREATE INDEX ON inh_a_1_b(id1);
-- we need to cache new plans so they can later be discarded
EXECUTE inh_a(1);
EXECUTE inh_b(1);
EXECUTE inh_a_1(1);
EXECUTE inh_a_1_b(1);

SELECT 't4' t, bypass, discard, query, relation
FROM ( SELECT *, unnest(relations)::regclass::text AS relation
       FROM pg_shared_plans_relations WHERE query LIKE '%inh%') s
ORDER BY query COLLATE "C", relation COLLATE "C", bypass, discard;

CREATE INDEX ON inh_a(id1);

SELECT 't5' t, bypass, discard, query, relation
FROM ( SELECT *, unnest(relations)::regclass::text AS relation
       FROM pg_shared_plans_relations WHERE query LIKE '%inh%') s
ORDER BY query COLLATE "C", relation COLLATE "C", bypass, discard;

INSERT INTO inh_a_1 SELECT 1;
PREPARE select_inh_1(int) AS SELECT * FROM inh_a WHERE id1 <= $1;
-- pg_stat_statements will generate the same queryid for this query, make sure
-- we see it as a different one
PREPARE select_inh_2(int) AS SELECT * FROM ONLY inh_a WHERE id1 <= $1;

EXECUTE select_inh_1(1);
EXECUTE select_inh_1(1);
EXECUTE select_inh_2(1);
EXECUTE select_inh_2(1);

-- We should see 2 entries, each having bypassed the planner once
SELECT 't6' t, bypass FROM pg_shared_plans WHERE query LIKE '%id1 <=%';
