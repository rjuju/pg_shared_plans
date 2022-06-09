SET pg_shared_plans.threshold = 1;
SET pg_shared_plans.min_plan_time = 0;
----------------------------
-- new in pg13: WITH TIES --
----------------------------

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
