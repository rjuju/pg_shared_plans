pg_shared_plans
===============

/!\ This extension is a POC, not ready for production /!\

pg_shared_plans is a PostgreSQL extension adding a transparent plan cache in
shared memory.

It can coexist with the current infrastucture for the local plan cache manager,
as plans that are not cached by pg_shared_plans can still be cached by it.

This extension requires pg_stat_statements to be installed, in order to
uniquely identify normalized queries.

Using the query identifier is not enough to uniquement identify a statements.
An additional constid hash is calculated for each entries based on the
constants still present in the queries.  Also, the userid will also be recorded
if the query depends on row level security enabled relations.

Installation
------------

- Compatible with PostgreSQL 12 and above
- Needs PostgreSQL header files
- Decompress the tarball or clone the repository
- `sudo make install`
- add pg_shared_plans and pg_stat_statements in shared_preload_libraries
- restart PostgreSQL

Configuration
-------------

The following configuration options are available:

- pg_shared_plans.enabled: Enable or disable pg_shared_plans (default: on)
- pg_shared_plans.max: Maximum number of plans to cache in shared memory
  (default: 200)
- pg_shared_plans.rdepend_max: Maximum number of entries to store per reverse
  dendency (default: 50)
- pg_shared_plans.min_plan_time: Minimum planning time for a plans to be cached
  in shared memory (default: 10ms)
- pg_shared_plans.threshold: Minimum number of custom plans to generate before
  choosing cached plans (default: 4)
- pg_shared_plans.explain_costs: Display execution plans with COSTS option
  (default: off)
- pg_shared_plans.explain_format: Display execution plans with FORMAT option
  (default: text)
- pg_shared_plans.explain_verbose: Display execution plans with VERBOSE option
  (default: off)

Usage
-----

Plans will be cached automatically, and less used plans will automatically be
discarded as needed.

The following functions are available:

- pg_shared_plans_reset(userid, dbid, queryid): Remove the given entry /
  entries from the shared plan cache
- pg_shared_plans_info(): Displays the number of times entries have been
  automatically evicted, and the timestamp of the last time it happened
- pg_shared_plans(showrels, showplans): Display the list of entries cached,
  including the number of underlying relation, the size of the cached plan and
  other information, with or without the list of relations used in the plan,
  and with or without the execution plan.

Some views are also available, which automatically add information from
pg_stat_statements:

- pg_shared_plans: won't display the list of relations or the execution plans
- pg_shared_plans_relations: will display the list of relations
- pg_shared_plans_explain: will display the execution plans
- pg_shared_plans_all: will display both the list of relations and the
  execution plans

Example
-------

```
rjuju=# SET pg_shared_plans.threshold = 1;
rjuju=# SET pg_shared_plans.min_plan_time = '0ms';
rjuju=# SELECT pg_shared_plans_reset();
rjuju=# PREPARE demo (int) AS SELECT * FROM pg_stat_activity WHERE pid = $1;
rjuju=# EXECUTE demo(pg_backend_pid());
rjuju=# EXECUTE demo(pg_backend_pid());
```

Will give the following data in shared cache:

```
=# \x
=# SELECT * FROM pg_shared_plans_all;
-[ RECORD 1 ]----+--------------------------------------------------------------------
rolname          | <NULL>
datname          | rjuju
queryid          | -2350634349264184376
constid          | -653821897
numconst         | 1
bypass           | 1
size             | 33 kB
plantime         | 4.006952
avg_custom_cost  | 26.06625
num_custom_plans | 1
generic_cost     | 3.56625
num_relations    | 3
query            | PREPARE demo (int) AS SELECT * FROM pg_stat_activity WHERE pid = $1
relations        | {12429,1262,1260}
plan             | Nested Loop Left Join                                              +
                 |   Join Filter: (s.datid = d.oid)                                   +
                 |   ->  Hash Right Join                                              +
                 |         Hash Cond: (u.oid = s.usesysid)                            +
                 |         ->  Seq Scan on pg_authid u                                +
                 |         ->  Hash                                                   +
                 |               ->  Function Scan on pg_stat_get_activity s          +
                 |                     Filter: (pid = $1)                             +
                 |   ->  Seq Scan on pg_database d                                    +
                 |

=# WITH s AS (SELECT unnest(relations) AS relation, query
    FROM pg_shared_plans_relations)
SELECT query, array_agg(relname) AS relations
FROM s
LEFT JOIN pg_class c ON c.oid = s.relation
GROUP BY query;
-[ RECORD 1 ]------------------------------------------------------------------
query     | PREPARE demo (int) AS SELECT * FROM pg_stat_activity WHERE pid = $1
relations | {pg_stat_activity,pg_database,pg_authid}

```
