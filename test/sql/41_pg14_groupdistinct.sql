------------------------------------
-- new in pg14: GROUP BY DISTINCT --
------------------------------------

SELECT pg_shared_plans_reset();
-- pg_stat_statements will generate the same queryid for this query, make sure
-- we see it as a different one
PREPARE groupby_2(int) AS SELECT a, b, c
 FROM (VALUES ($1, 2, 3), (4, NULL, 6), (7, 8, 9)) AS t (a, b, c)
 GROUP BY DISTINCT ROLLUP(a, b), rollup(a, c)
 ORDER BY a, b, c;

EXECUTE groupby_2(1);
EXECUTE groupby_2(1);

-- We should see 1 entry, having bypassed the planner once
SELECT bypass FROM pg_shared_plans WHERE query LIKE '%SELECT a, b, c%';
