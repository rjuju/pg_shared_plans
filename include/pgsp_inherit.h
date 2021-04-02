/*-------------------------------------------------------------------------
 *
 * pgsp_inherit.h: Some functions to handle inheritance children.
 *
 * This program is open source, licensed under the PostgreSQL license.
 * For license terms, see the LICENSE file.
 *
 * Copyright (C) 2021: Julien Rouhaud
 *
 *-------------------------------------------------------------------------
 */

#ifndef _PGSP_INHERITT_H
#define _PGSP_INHERITT_H

#include "postgres.h"


List *pgsp_get_inheritance_ancestors(Oid relid);
#endif
