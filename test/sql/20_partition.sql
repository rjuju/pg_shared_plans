SET pg_shared_plans.threshold = 1;
SELECT pg_shared_plans_reset();
-- we'll often discard cached plans, to make sure plancache won't choose its
-- own cached plans.
SET plan_cache_mode TO force_custom_plan;

CREATE TABLE part_list(id1 integer, id2 integer) PARTITION BY LIST (id1);

PREPARE part_list(int) AS SELECT id1 FROM part_list WHERE id1 = $1;
EXECUTE part_list(1);
EXECUTE part_list(1);

SELECT 't1' t, bypass, discard, query, relation
FROM ( SELECT *, unnest(relations)::regclass::text AS relation
       FROM pg_shared_plans_relations WHERE query LIKE '%part_list%') s
ORDER BY query COLLATE "C", relation COLLATE "C", bypass, discard;

-- creating a table in a partitioning tree should discard entries depending on
-- any of the parent partitions
CREATE TABLE part_list_1 PARTITION OF part_list FOR VALUES IN (1) PARTITION BY LIST (id1);

PREPARE part_list_1(int) AS SELECT id1 FROM part_list_1 WHERE id1 = $1;

-- we need to cache a new plan so it can later be discarded
EXECUTE part_list(1);
EXECUTE part_list_1(1);
EXECUTE part_list_1(1);

SELECT 't2' t, bypass, discard, query, relation
FROM ( SELECT *, unnest(relations)::regclass::text AS relation
       FROM pg_shared_plans_relations WHERE query LIKE '%part_list%') s
ORDER BY query COLLATE "C", relation COLLATE "C", bypass, discard;

CREATE TABLE part_list_1_1 PARTITION OF part_list_1 FOR VALUES IN (1);

PREPARE part_list_1_1(int) AS SELECT id1 FROM part_list_1_1 WHERE id1 = $1;
-- we need to cache new plans so it can later be discarded
EXECUTE part_list(1);
EXECUTE part_list_1(1);
EXECUTE part_list_1_1(1);
EXECUTE part_list_1_1(1);

SELECT 't3' t, bypass, discard, query, relation
FROM ( SELECT *, unnest(relations)::regclass::text AS relation
       FROM pg_shared_plans_relations WHERE query LIKE '%part_list%') s
ORDER BY query COLLATE "C", relation COLLATE "C", bypass, discard;

CREATE INDEX ON part_list_1_1(id1);

-- we need to cache new plans so it can later be discarded
EXECUTE part_list(1);
EXECUTE part_list_1(1);
EXECUTE part_list_1_1(1);

SELECT 't4' t, bypass, discard, query, relation
FROM ( SELECT *, unnest(relations)::regclass::text AS relation
       FROM pg_shared_plans_relations WHERE query LIKE '%part_list%') s
ORDER BY query COLLATE "C", relation COLLATE "C", bypass, discard;

BEGIN;
CREATE INDEX ON part_list(id1);
ROLLBACK;

-- we need to cache new plans so it can later be discarded
EXECUTE part_list(1);
EXECUTE part_list_1(1);
EXECUTE part_list_1_1(1);

SELECT 't5a' t, bypass, discard, query, relation
FROM ( SELECT *, unnest(relations)::regclass::text AS relation
       FROM pg_shared_plans_relations WHERE query LIKE '%part_list%') s
ORDER BY query COLLATE "C", relation COLLATE "C", bypass, discard;

BEGIN;
CREATE INDEX ON part_list(id1);
COMMIT;

-- we need to cache new plans so it can later be discarded
EXECUTE part_list(1);
EXECUTE part_list_1(1);
EXECUTE part_list_1_1(1);

SELECT 't5b' t, bypass, discard, query, relation
FROM ( SELECT *, unnest(relations)::regclass::text AS relation
       FROM pg_shared_plans_relations WHERE query LIKE '%part_list%') s
ORDER BY query COLLATE "C", relation COLLATE "C", bypass, discard;

-- should not discard anything
CREATE TABLE part_list_1_2(id1 integer, id2 integer);

PREPARE part_list_1_2(int) AS SELECT id1 FROM part_list_1_2 WHERE id1 = $1;

EXECUTE part_list(1);
EXECUTE part_list_1(1);
EXECUTE part_list_1_1(1);
EXECUTE part_list_1_2(1);
EXECUTE part_list_1_2(1);

SELECT 't6' t, bypass, discard, query, relation
FROM ( SELECT *, unnest(relations)::regclass::text AS relation
       FROM pg_shared_plans_relations WHERE query LIKE '%part_list%') s
ORDER BY query COLLATE "C", relation COLLATE "C", bypass, discard;

-- Should only discard plans depending on part_list_1 and part_list
ALTER TABLE part_list_1 ATTACH PARTITION part_list_1_2 FOR VALUES IN (2);

EXECUTE part_list(1);
EXECUTE part_list_1(1);
EXECUTE part_list_1_1(1);
EXECUTE part_list_1_2(1);

SELECT 't7' t, bypass, discard, query, relation
FROM ( SELECT *, unnest(relations)::regclass::text AS relation
       FROM pg_shared_plans_relations WHERE query LIKE '%part_list%') s
ORDER BY query COLLATE "C", relation COLLATE "C", bypass, discard;

-- Should only discard plans depending on part_list_1 and part_list
ALTER TABLE part_list_1 DETACH PARTITION part_list_1_2;

EXECUTE part_list(1);
EXECUTE part_list_1(1);
EXECUTE part_list_1_1(1);
EXECUTE part_list_1_2(1);

SELECT 't8' t, bypass, discard, query, relation
FROM ( SELECT *, unnest(relations)::regclass::text AS relation
       FROM pg_shared_plans_relations WHERE query LIKE '%part_list%') s
ORDER BY query COLLATE "C", relation COLLATE "C", bypass, discard;

-- Should discard all plans depending on still attached partitions
ALTER TABLE part_list ALTER COLUMN id2 TYPE bigint;

EXECUTE part_list(1);
EXECUTE part_list_1(1);
EXECUTE part_list_1_1(1);
EXECUTE part_list_1_2(1);

SELECT 't9' t, bypass, discard, query, relation
FROM ( SELECT *, unnest(relations)::regclass::text AS relation
       FROM pg_shared_plans_relations WHERE query LIKE '%part_list%') s
ORDER BY query COLLATE "C", relation COLLATE "C", bypass, discard;
