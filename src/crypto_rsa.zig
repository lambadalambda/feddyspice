const std = @import("std");

const c = @cImport({
    @cInclude("openssl/bio.h");
    @cInclude("openssl/bn.h");
    @cInclude("openssl/buffer.h");
    @cInclude("openssl/evp.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/rsa.h");
});

pub const Error = std.mem.Allocator.Error || error{
    OpenSslFailure,
};

pub const KeyPair = struct {
    private_key_pem: []const u8,
    public_key_pem: []const u8,
};

fn bioToOwnedSlice(allocator: std.mem.Allocator, bio: *c.BIO) Error![]u8 {
    var mem_ptr: ?*c.BUF_MEM = null;
    _ = c.BIO_get_mem_ptr(bio, &mem_ptr);
    if (mem_ptr == null) return error.OpenSslFailure;
    if (mem_ptr.?.data == null) return error.OpenSslFailure;

    const len: usize = @intCast(mem_ptr.?.length);
    const data_ptr: [*]const u8 = @ptrCast(mem_ptr.?.data);
    return allocator.dupe(u8, data_ptr[0..len]);
}

pub fn generateRsaKeyPairPem(allocator: std.mem.Allocator, bits: u32) Error!KeyPair {
    var rsa: ?*c.RSA = c.RSA_new();
    if (rsa == null) return error.OpenSslFailure;
    errdefer if (rsa) |r| c.RSA_free(r);

    const e = c.BN_new() orelse return error.OpenSslFailure;
    defer c.BN_free(e);

    if (c.BN_set_word(e, c.RSA_F4) != 1) return error.OpenSslFailure;
    if (c.RSA_generate_key_ex(rsa.?, @intCast(bits), e, null) != 1) return error.OpenSslFailure;

    const pkey = c.EVP_PKEY_new() orelse return error.OpenSslFailure;
    defer c.EVP_PKEY_free(pkey);

    if (c.EVP_PKEY_assign_RSA(pkey, rsa.?) != 1) return error.OpenSslFailure;
    rsa = null; // Owned by pkey now.

    const bio_priv = c.BIO_new(c.BIO_s_mem()) orelse return error.OpenSslFailure;
    defer _ = c.BIO_free(bio_priv);
    if (c.PEM_write_bio_PrivateKey(bio_priv, pkey, null, null, 0, null, null) != 1) {
        return error.OpenSslFailure;
    }
    const private_key_pem = try bioToOwnedSlice(allocator, bio_priv);

    const bio_pub = c.BIO_new(c.BIO_s_mem()) orelse return error.OpenSslFailure;
    defer _ = c.BIO_free(bio_pub);
    if (c.PEM_write_bio_PUBKEY(bio_pub, pkey) != 1) return error.OpenSslFailure;
    const public_key_pem = try bioToOwnedSlice(allocator, bio_pub);

    return .{
        .private_key_pem = private_key_pem,
        .public_key_pem = public_key_pem,
    };
}

pub fn signRsaSha256Pem(
    allocator: std.mem.Allocator,
    private_key_pem: []const u8,
    msg: []const u8,
) Error![]u8 {
    const bio = c.BIO_new_mem_buf(@ptrCast(private_key_pem.ptr), @intCast(private_key_pem.len)) orelse
        return error.OpenSslFailure;
    defer _ = c.BIO_free(bio);

    const pkey = c.PEM_read_bio_PrivateKey(bio, null, null, null) orelse return error.OpenSslFailure;
    defer c.EVP_PKEY_free(pkey);

    const md_ctx = c.EVP_MD_CTX_new() orelse return error.OpenSslFailure;
    defer c.EVP_MD_CTX_free(md_ctx);

    if (c.EVP_DigestSignInit(md_ctx, null, c.EVP_sha256(), null, pkey) != 1) return error.OpenSslFailure;
    if (c.EVP_DigestSignUpdate(md_ctx, msg.ptr, msg.len) != 1) return error.OpenSslFailure;

    var sig_len: usize = 0;
    if (c.EVP_DigestSignFinal(md_ctx, null, &sig_len) != 1) return error.OpenSslFailure;

    var sig = try allocator.alloc(u8, sig_len);
    errdefer allocator.free(sig);

    if (c.EVP_DigestSignFinal(md_ctx, sig.ptr, &sig_len) != 1) return error.OpenSslFailure;
    return sig[0..sig_len];
}

pub fn verifyRsaSha256Pem(
    public_key_pem: []const u8,
    msg: []const u8,
    sig: []const u8,
) error{OpenSslFailure}!bool {
    const bio = c.BIO_new_mem_buf(@ptrCast(public_key_pem.ptr), @intCast(public_key_pem.len)) orelse
        return error.OpenSslFailure;
    defer _ = c.BIO_free(bio);

    const pkey = c.PEM_read_bio_PUBKEY(bio, null, null, null) orelse return error.OpenSslFailure;
    defer c.EVP_PKEY_free(pkey);

    const md_ctx = c.EVP_MD_CTX_new() orelse return error.OpenSslFailure;
    defer c.EVP_MD_CTX_free(md_ctx);

    if (c.EVP_DigestVerifyInit(md_ctx, null, c.EVP_sha256(), null, pkey) != 1) return error.OpenSslFailure;
    if (c.EVP_DigestVerifyUpdate(md_ctx, msg.ptr, msg.len) != 1) return error.OpenSslFailure;

    return c.EVP_DigestVerifyFinal(md_ctx, sig.ptr, sig.len) == 1;
}

test "generate + sign + verify" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const kp = try generateRsaKeyPairPem(a, 512);
    try std.testing.expect(std.mem.indexOf(u8, kp.public_key_pem, "BEGIN PUBLIC KEY") != null);
    try std.testing.expect(std.mem.indexOf(u8, kp.private_key_pem, "BEGIN") != null);

    const msg = "hello";
    const sig = try signRsaSha256Pem(a, kp.private_key_pem, msg);
    try std.testing.expect(try verifyRsaSha256Pem(kp.public_key_pem, msg, sig));
    try std.testing.expect(!(try verifyRsaSha256Pem(kp.public_key_pem, "nope", sig)));
}
