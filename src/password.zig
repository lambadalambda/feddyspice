const std = @import("std");

pub const SaltLen = 16;
pub const HashLen = 32;

pub const Salt = [SaltLen]u8;
pub const Hash = [HashLen]u8;

pub const Params = std.crypto.pwhash.argon2.Params;
pub const Mode: std.crypto.pwhash.argon2.Mode = .argon2id;

pub const Error = std.crypto.pwhash.KdfError;

pub fn hashPassword(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: Salt,
    params: Params,
) Error!Hash {
    var out: Hash = undefined;
    try std.crypto.pwhash.argon2.kdf(
        allocator,
        out[0..],
        password,
        salt[0..],
        params,
        Mode,
    );
    return out;
}

pub fn verifyPassword(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: Salt,
    expected_hash: Hash,
    params: Params,
) Error!bool {
    const actual = try hashPassword(allocator, password, salt, params);
    return std.crypto.timing_safe.eql(Hash, actual, expected_hash);
}

test "hash + verify" {
    const params: Params = .{ .t = 1, .m = 8, .p = 1 };
    const salt: Salt = .{0x01} ** SaltLen;

    const hash = try hashPassword(std.testing.allocator, "hunter2", salt, params);

    try std.testing.expect(try verifyPassword(std.testing.allocator, "hunter2", salt, hash, params));
    try std.testing.expect(!(try verifyPassword(std.testing.allocator, "wrong", salt, hash, params)));
}
