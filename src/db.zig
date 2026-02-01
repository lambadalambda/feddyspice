const std = @import("std");

const c = @cImport({
    @cInclude("sqlite3.h");
});

extern fn feddyspice_bind_text_transient(stmt: *c.sqlite3_stmt, idx: c_int, value: [*c]const u8, n: c_int) c_int;
extern fn feddyspice_bind_blob_transient(stmt: *c.sqlite3_stmt, idx: c_int, value: ?*const anyopaque, n: c_int) c_int;

pub const Error = error{
    Sqlite,
};

pub const Db = struct {
    handle: *c.sqlite3,

    pub fn openZ(path: [:0]const u8) Error!Db {
        var db_ptr: ?*c.sqlite3 = null;
        const flags = c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_CREATE | c.SQLITE_OPEN_NOMUTEX;
        const rc = c.sqlite3_open_v2(path.ptr, &db_ptr, flags, null);
        if (rc != c.SQLITE_OK or db_ptr == null) {
            if (db_ptr) |db| _ = c.sqlite3_close(db);
            return error.Sqlite;
        }
        return .{ .handle = db_ptr.? };
    }

    pub fn open(allocator: std.mem.Allocator, path: []const u8) (Error || std.mem.Allocator.Error)!Db {
        const path_z = try allocator.dupeZ(u8, path);
        defer allocator.free(path_z);
        return openZ(path_z);
    }

    pub fn close(db: *Db) void {
        _ = c.sqlite3_close(db.handle);
        db.* = undefined;
    }

    pub fn execZ(db: *Db, sql: [:0]const u8) Error!void {
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(db.handle, sql.ptr, null, null, @ptrCast(&err_msg));
        if (rc != c.SQLITE_OK) {
            if (err_msg != null) c.sqlite3_free(err_msg);
            return error.Sqlite;
        }
    }

    pub fn prepareZ(db: *Db, sql: [:0]const u8) Error!Stmt {
        var stmt_ptr: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(db.handle, sql.ptr, -1, &stmt_ptr, null);
        if (rc != c.SQLITE_OK or stmt_ptr == null) return error.Sqlite;
        return .{ .stmt = stmt_ptr.? };
    }

    pub fn lastInsertRowId(db: *Db) i64 {
        return c.sqlite3_last_insert_rowid(db.handle);
    }

    pub fn changes(db: *Db) i64 {
        return c.sqlite3_changes(db.handle);
    }
};

pub const Stmt = struct {
    stmt: *c.sqlite3_stmt,

    pub fn finalize(s: *Stmt) void {
        _ = c.sqlite3_finalize(s.stmt);
        s.* = undefined;
    }

    pub fn reset(s: *Stmt) void {
        _ = c.sqlite3_reset(s.stmt);
        _ = c.sqlite3_clear_bindings(s.stmt);
    }

    pub fn bindInt64(s: *Stmt, index: usize, value: i64) Error!void {
        const rc = c.sqlite3_bind_int64(s.stmt, @intCast(index), value);
        if (rc != c.SQLITE_OK) return error.Sqlite;
    }

    pub fn bindText(s: *Stmt, index: usize, value: []const u8) Error!void {
        const ptr: [*c]const u8 = if (value.len == 0) "" else value.ptr;
        const rc = feddyspice_bind_text_transient(s.stmt, @intCast(index), ptr, @intCast(value.len));
        if (rc != c.SQLITE_OK) return error.Sqlite;
    }

    pub fn bindBlob(s: *Stmt, index: usize, value: []const u8) Error!void {
        const ptr: ?*const anyopaque = if (value.len == 0) null else @ptrCast(value.ptr);
        const rc = feddyspice_bind_blob_transient(s.stmt, @intCast(index), ptr, @intCast(value.len));
        if (rc != c.SQLITE_OK) return error.Sqlite;
    }

    pub fn bindNull(s: *Stmt, index: usize) Error!void {
        const rc = c.sqlite3_bind_null(s.stmt, @intCast(index));
        if (rc != c.SQLITE_OK) return error.Sqlite;
    }

    pub const Step = enum { row, done };

    pub fn step(s: *Stmt) Error!Step {
        const rc = c.sqlite3_step(s.stmt);
        return switch (rc) {
            c.SQLITE_ROW => .row,
            c.SQLITE_DONE => .done,
            else => error.Sqlite,
        };
    }

    pub fn columnInt64(s: *Stmt, col: usize) i64 {
        return c.sqlite3_column_int64(s.stmt, @intCast(col));
    }

    pub fn columnText(s: *Stmt, col: usize) []const u8 {
        const ptr = c.sqlite3_column_text(s.stmt, @intCast(col)) orelse return "";
        const len: usize = @intCast(c.sqlite3_column_bytes(s.stmt, @intCast(col)));
        return ptr[0..len];
    }

    pub fn columnBlob(s: *Stmt, col: usize) []const u8 {
        const ptr = c.sqlite3_column_blob(s.stmt, @intCast(col)) orelse return "";
        const len: usize = @intCast(c.sqlite3_column_bytes(s.stmt, @intCast(col)));
        return @as([*]const u8, @ptrCast(ptr))[0..len];
    }

    pub const ColumnType = enum { integer, float, text, blob, null };

    pub fn columnType(s: *Stmt, col: usize) ColumnType {
        return switch (c.sqlite3_column_type(s.stmt, @intCast(col))) {
            c.SQLITE_INTEGER => .integer,
            c.SQLITE_FLOAT => .float,
            c.SQLITE_TEXT => .text,
            c.SQLITE_BLOB => .blob,
            else => .null,
        };
    }
};
