-- This program is open source, licensed under the PostgreSQL License.
-- For license terms, see the LICENSE file.
--
-- Copyright (C) 2021: Julien Rouhaud

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
--\echo Use "CREATE EXTENSION pg_shared_plans" to load this file. \quit

--- Define pg_shared_plans_info
CREATE FUNCTION pg_shared_plans_info(
    OUT rdepend_num int,
    OUT rdepend_size bigint,
    OUT dealloc bigint,
    OUT stats_reset timestamp with time zone
)
RETURNS record
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT VOLATILE PARALLEL SAFE;

CREATE VIEW pg_shared_plans_info AS
  SELECT * FROM pg_shared_plans_info();

GRANT SELECT ON pg_shared_plans_info TO PUBLIC;

CREATE FUNCTION pg_shared_plans_reset(IN userid Oid DEFAULT 0,
    IN dbid Oid DEFAULT 0,
    IN queryid bigint DEFAULT 0
)
RETURNS void
AS 'MODULE_PATHNAME', 'pg_shared_plans_reset'
LANGUAGE C STRICT PARALLEL SAFE;

-- Don't want this to be available to non-superusers.
REVOKE ALL ON FUNCTION pg_shared_plans_reset(Oid, Oid, bigint) FROM PUBLIC;

CREATE FUNCTION pg_shared_plans(IN showplan boolean DEFAULT false,
    IN showrels boolean DEFAULT false,
    IN  dbid oid DEFAULT 0, in relid oid DEFAULT 0,
    OUT userid oid,
    OUT dbid oid,
    OUT queryid bigint,
    OUT constid integer,
    OUT numconst integer,
    OUT bypass int8,
    OUT size int8,
    OUT plantime float8,
    OUT total_custom_cost float8,
    OUT num_custom_plans bigint,
    OUT generic_cost float8,
    OUT num_relations integer,
    OUT discard bigint,
    OUT lockers integer,
    OUT relations oid[],
    OUT plan text)
RETURNS SETOF record
AS 'MODULE_PATHNAME', 'pg_shared_plans'
LANGUAGE C STRICT VOLATILE PARALLEL SAFE;

CREATE VIEW pg_shared_plans AS
  SELECT DISTINCT
    r.rolname,
    d.datname,
    pgsp.queryid,
    pgsp.constid,
    pgsp.numconst,
    pgsp.bypass,
    pg_size_pretty(pgsp.size) AS size,
    pgsp.plantime,
    pgsp.total_custom_cost / num_custom_plans AS avg_custom_cost,
    pgsp.num_custom_plans,
    pgsp.generic_cost,
    pgsp.num_relations,
    pgsp.discard,
    pgsp.lockers,
    pgss.query
  FROM pg_shared_plans(false, false) AS pgsp
  LEFT JOIN pg_stat_statements AS pgss USING (dbid, queryid)
  LEFT JOIN pg_roles AS r ON r.oid = pgsp.userid
  LEFT JOIN pg_database AS d ON d.oid = pgsp.dbid;

CREATE VIEW pg_shared_plans_relations AS
  SELECT DISTINCT
    r.rolname,
    d.datname,
    pgsp.numconst,
    pgsp.bypass,
    pg_size_pretty(pgsp.size) AS size,
    pgsp.plantime,
    pgsp.total_custom_cost / num_custom_plans AS avg_custom_cost,
    pgsp.num_custom_plans,
    pgsp.generic_cost,
    pgsp.num_relations,
    pgsp.discard,
    pgsp.lockers,
    pgss.query,
    pgsp.relations
  FROM pg_shared_plans(true, false) AS pgsp
  LEFT JOIN pg_stat_statements AS pgss USING (dbid, queryid)
  LEFT JOIN pg_roles AS r ON r.oid = pgsp.userid
  LEFT JOIN pg_database AS d ON d.oid = pgsp.dbid;

CREATE VIEW pg_shared_plans_explain AS
  SELECT DISTINCT
    r.rolname,
    d.datname,
    pgsp.queryid,
    pgsp.constid,
    pgsp.numconst,
    pgsp.bypass,
    pg_size_pretty(pgsp.size) AS size,
    pgsp.plantime,
    pgsp.total_custom_cost / num_custom_plans AS avg_custom_cost,
    pgsp.num_custom_plans,
    pgsp.generic_cost,
    pgsp.num_relations,
    pgsp.discard,
    pgsp.lockers,
    pgss.query,
    pgsp.plan
  FROM pg_shared_plans(false, true) AS pgsp
  LEFT JOIN pg_stat_statements AS pgss USING (dbid, queryid)
  LEFT JOIN pg_roles AS r ON r.oid = pgsp.userid
  LEFT JOIN pg_database AS d ON d.oid = pgsp.dbid;

CREATE VIEW pg_shared_plans_all AS
  SELECT DISTINCT
    r.rolname,
    d.datname,
    pgsp.queryid,
    pgsp.constid,
    pgsp.numconst,
    pgsp.bypass,
    pg_size_pretty(pgsp.size) AS size,
    pgsp.plantime,
    pgsp.total_custom_cost / num_custom_plans AS avg_custom_cost,
    pgsp.num_custom_plans,
    pgsp.generic_cost,
    pgsp.num_relations,
    pgsp.discard,
    pgsp.lockers,
    pgss.query,
    pgsp.relations,
    pgsp.plan
  FROM pg_shared_plans(true, true) AS pgsp
  LEFT JOIN pg_stat_statements AS pgss USING (dbid, queryid)
  LEFT JOIN pg_roles AS r ON r.oid = pgsp.userid
  LEFT JOIN pg_database AS d ON d.oid = pgsp.dbid;

GRANT SELECT ON pg_shared_plans TO pg_read_all_stats;
