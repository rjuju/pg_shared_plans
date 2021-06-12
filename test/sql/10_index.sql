SET pg_shared_plans.threshold = 1;
SELECT pg_shared_plans_reset();
-- Dropped index
CREATE TABLE t_ind AS SELECT id FROM generate_series(1, 10000) id;
CREATE INDEX t_ind_idx ON t_ind (id);
VACUUM ANALYZE t_ind;

PREPARE t_ind (int) AS SELECT id FROM t_ind WHERE id = $1;

EXECUTE t_ind(1);
EXECUTE t_ind(1);
SELECT discard, bypass FROM pg_shared_plans WHERE query LIKE '%t_ind%';

DROP INDEX t_ind_idx;
-- cached plan should be discarded, entry preserved
EXECUTE t_ind(1);
-- plan should have been discarded once, and kept its previous counters
SELECT discard, bypass, lockers FROM pg_shared_plans WHERE query LIKE '%t_ind%';

CREATE INDEX t_ind_idx ON t_ind (id);
-- cached plan should be discarded, entry preserved
EXECUTE t_ind(1);
-- plan should have been discarded twice, and kept its previous counters
SELECT discard, bypass, lockers FROM pg_shared_plans WHERE query LIKE '%t_ind%';

DROP INDEX CONCURRENTLY t_ind_idx;
-- cached plan should be discarded, entry preserved
EXECUTE t_ind(1);
-- plan should have been discarded 3 times, and kept its previous counters
SELECT discard, bypass, lockers FROM pg_shared_plans WHERE query LIKE '%t_ind%';
