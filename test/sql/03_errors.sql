-- test nested call of pg_shared_plans()
SELECT pg_shared_plans_reset(coalesce(userid, 0), dbid, queryid)
FROM pg_shared_plans()
LIMIT 1;

-- reset the rest of the entries
SELECT pg_shared_plans_reset();

SELECT rdepend_num, alloced_size FROM pg_shared_plans_info;

--  Check error on max rdepend size
SET pg_shared_plans.threshold = 1;
SET pg_shared_plans.min_plan_time = 0;

CREATE TABLE rdepend(id int);
CREATE FUNCTION rfunc() RETURNS int AS $$
BEGIN
    RETURN 1;
END;
$$ VOLATILE LANGUAGE plpgsql;

-- create more than pg_shared_plans.rdepend_max entries with different queryid
-- with dependencies on a single function and a single table
SELECT 'PREPARE rdepend_' || i || '(int) AS SELECT count(*)'
    ' FROM ('
    '   SELECT ' || string_agg('1', ',') || ', rfunc() FROM rdepend) s'
FROM generate_series(1, 50) i, generate_series(1, i) j
GROUP BY i
ORDER by i \gexec

SELECT 'EXECUTE rdepend_' || i || '(1)'
FROM generate_series(1, 50) i \gexec

-- test failure on relation reverse dependency
PREPARE rdepend_fail_1(int) AS SELECT * FROM rdepend WHERE id < $1;
EXECUTE rdepend_fail_1(1);

SELECT count(*) FROM pg_shared_plans;

-- test failure on proc reverse dependency
PREPARE rdepend_fail_2(int) AS SELECT rfunc() FROM pg_class WHERE oid = $1;
EXECUTE rdepend_fail_2(1);

SELECT count(*) FROM pg_shared_plans;

SELECT pg_shared_plans_reset();

SELECT rdepend_num, alloced_size FROM pg_shared_plans_info;
