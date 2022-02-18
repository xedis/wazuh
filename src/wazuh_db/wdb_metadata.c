/*
 * Wazuh SQLite integration
 * Copyright (C) 2015, Wazuh Inc.
 * June 06, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"


typedef enum wdb_stmt_metadata {
    WDB_STMT_METADATA_FIND,
    WDB_STMT_METADATA_TABLE_CHECK
} wdb_stmt_metadata;

static const char *SQL_METADATA_STMT[] = {
    "SELECT value FROM metadata WHERE key = ?;",
    "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?;"
};

int wdb_metadata_get_entry(wdb_t * wdb, const char *key, char *output) {
    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(wdb->db,
                            SQL_METADATA_STMT[WDB_STMT_METADATA_FIND],
                            -1,
                            &stmt,
                            NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_prepare_v2(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, key, -1, NULL);

    switch (sqlite3_step(stmt)) {
        case SQLITE_ROW:
            snprintf(output, OS_SIZE_256 + 1, "%s", (char *)sqlite3_column_text(stmt, 0));
            sqlite3_finalize(stmt);
            return 1;
            break;
        case SQLITE_DONE:
            sqlite3_finalize(stmt);
            return 0;
            break;
        default:
            mdebug1("DB(%s) sqlite3_step(): %s", wdb->id, sqlite3_errmsg(wdb->db));
            sqlite3_finalize(stmt);
            return -1;
    }
}

int wdb_metadata_table_check(wdb_t * wdb, const char * key) {
    sqlite3_stmt *stmt = NULL;
    int ret = OS_INVALID;

    if (sqlite3_prepare_v2(wdb->db,
                            SQL_METADATA_STMT[WDB_STMT_METADATA_TABLE_CHECK],
                            -1,
                            &stmt,
                            NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_prepare_v2(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    if (sqlite3_bind_text(stmt, 1, key, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        sqlite3_finalize(stmt);
        return OS_INVALID;
    }

    switch (sqlite3_step(stmt)) {
    case SQLITE_ROW:
        ret = (int)sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        return ret;
        break;
    default:
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        sqlite3_finalize(stmt);
        return OS_INVALID;
    }
}
