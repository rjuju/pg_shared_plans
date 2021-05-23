DROP ROLE regress_a;
DROP ROLE regress_b;
DROP ROLE regress_c;
SELECT pg_shared_plans_reset();

SELECT rdepend_num, alloced_size FROM pg_shared_plans_info;
