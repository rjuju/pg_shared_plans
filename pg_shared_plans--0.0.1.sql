-- This program is open source, licensed under the PostgreSQL License.
-- For license terms, see the LICENSE file.
--
-- Copyright (C) 2021: Julien Rouhaud

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_shared_plans" to load this file. \quit

--- Define pg_shared_plans_info
CREATE FUNCTION pg_shared_plans_info(
    OUT dealloc bigint,
    OUT stats_reset timestamp with time zone
)
RETURNS record
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT VOLATILE PARALLEL SAFE;

CREATE VIEW pg_shared_plans_info AS
  SELECT * FROM pg_shared_plans_info();

GRANT SELECT ON pg_shared_plans_info TO PUBLIC;

CREATE FUNCTION pg_shared_plans_reset(IN dbid Oid DEFAULT 0,
    IN queryid bigint DEFAULT 0
)
RETURNS void
AS 'MODULE_PATHNAME', 'pg_shared_plans_reset'
LANGUAGE C STRICT PARALLEL SAFE;

-- Don't want this to be available to non-superusers.
REVOKE ALL ON FUNCTION pg_shared_plans_reset(Oid, bigint) FROM PUBLIC;

CREATE FUNCTION pg_shared_plans(IN showplan boolean,
    OUT dbid oid,
    OUT queryid bigint,
    OUT bypass int8,
    OUT plan text)
RETURNS SETOF record
AS 'MODULE_PATHNAME', 'pg_shared_plans'
LANGUAGE C STRICT VOLATILE PARALLEL SAFE;

CREATE VIEW pg_shared_plans AS
  SELECT DISTINCT pgss.query, pgsp.*
  FROM pg_shared_plans(true) AS pgsp
  LEFT JOIN pg_stat_statements AS pgss USING (dbid, queryid);

GRANT SELECT ON pg_shared_plans TO pg_read_all_stats;
