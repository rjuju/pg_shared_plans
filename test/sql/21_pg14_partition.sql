SET pg_shared_plans.threshold = 1;
SET pg_shared_plans.min_plan_time = 0;
PREPARE part_list(int) AS SELECT id1 FROM part_list WHERE id1 = $1;
PREPARE part_list_1(int) AS SELECT id1 FROM part_list_1 WHERE id1 = $1;
PREPARE part_list_1_1(int) AS SELECT id1 FROM part_list_1_1 WHERE id1 = $1;
PREPARE part_list_1_2(int) AS SELECT id1 FROM part_list_1_2 WHERE id1 = $1;

-- Should only discard plans depending on part_list_1 and part_list
ALTER TABLE part_list_1 DETACH PARTITION part_list_1_1 CONCURRENTLY;

EXECUTE part_list(1);
EXECUTE part_list_1(1);
EXECUTE part_list_1_1(1);
EXECUTE part_list_1_2(1);

SELECT 't10' t, bypass, discard, query, relation
FROM ( SELECT *, unnest(relations)::regclass::text AS relation
       FROM pg_shared_plans_relations WHERE query LIKE '%part_list%') s
ORDER BY query COLLATE "C", relation COLLATE "C", bypass, discard;

ALTER TABLE part_list_1 ATTACH PARTITION part_list_1_1 FOR VALUES IN (1);
INSERT INTO part_list SELECT 1, 2;
PREPARE select_part_1(int) AS SELECT * FROM part_list WHERE id1 <= $1;
-- pg_stat_statements will generate the same queryid for this query, make sure
-- we see it as a different one
PREPARE select_part_2(int) AS SELECT * FROM ONLY part_list WHERE id1 <= $1;

EXECUTE select_part_1(1);
EXECUTE select_part_1(1);
EXECUTE select_part_2(1);
EXECUTE select_part_2(1);

-- We should see 2 entries, each having bypassed the planner once
SELECT 't11' t, bypass FROM pg_shared_plans WHERE query LIKE '%id1 <=%';
