#include <sqlite3.h>

int feddyspice_bind_text_transient(sqlite3_stmt *stmt, int idx, const char *value, int n) {
    return sqlite3_bind_text(stmt, idx, value, n, SQLITE_TRANSIENT);
}

int feddyspice_bind_blob_transient(sqlite3_stmt *stmt, int idx, const void *value, int n) {
    return sqlite3_bind_blob(stmt, idx, value, n, SQLITE_TRANSIENT);
}

