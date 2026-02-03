const std = @import("std");

pub fn isAllowedAddress(addr: std.net.Address, allow_private_networks: bool) bool {
    switch (addr.any.family) {
        std.posix.AF.INET => {
            const bytes: *const [4]u8 = @ptrCast(&addr.in.sa.addr);
            return isAllowedIPv4(bytes.*, allow_private_networks);
        },
        std.posix.AF.INET6 => return isAllowedIPv6(addr.in6.sa.addr, allow_private_networks),
        else => return false,
    }
}

fn isAllowedIPv4(ip: [4]u8, allow_private_networks: bool) bool {
    // 0.0.0.0/8 "this network" (includes 0.0.0.0 unspecified)
    if (ip[0] == 0) return false;

    // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved + 255.255.255.255 broadcast
    if (ip[0] >= 224) return false;

    // Private / local ranges
    if (ip[0] == 10) return allow_private_networks; // 10.0.0.0/8
    if (ip[0] == 127) return allow_private_networks; // 127.0.0.0/8 loopback
    if (ip[0] == 169 and ip[1] == 254) return allow_private_networks; // 169.254.0.0/16 link-local
    if (ip[0] == 172 and ip[1] >= 16 and ip[1] <= 31) return allow_private_networks; // 172.16.0.0/12
    if (ip[0] == 192 and ip[1] == 168) return allow_private_networks; // 192.168.0.0/16
    if (ip[0] == 100 and ip[1] >= 64 and ip[1] <= 127) return allow_private_networks; // 100.64.0.0/10 CGNAT
    if (ip[0] == 198 and (ip[1] == 18 or ip[1] == 19)) return allow_private_networks; // 198.18.0.0/15 benchmark

    return true;
}

fn isAllowedIPv6(ip: [16]u8, allow_private_networks: bool) bool {
    // :: unspecified
    if (std.mem.allEqual(u8, ip[0..], 0)) return false;

    // ff00::/8 multicast
    if (ip[0] == 0xff) return false;

    if (isIpv4Mapped(ip)) {
        const v4: [4]u8 = .{ ip[12], ip[13], ip[14], ip[15] };
        return isAllowedIPv4(v4, allow_private_networks);
    }

    // ::1 loopback
    if (std.mem.allEqual(u8, ip[0..15], 0) and ip[15] == 1) return allow_private_networks;

    // fc00::/7 unique local
    if ((ip[0] & 0xfe) == 0xfc) return allow_private_networks;

    // fe80::/10 link-local unicast
    if (ip[0] == 0xfe and (ip[1] & 0xc0) == 0x80) return allow_private_networks;

    return true;
}

fn isIpv4Mapped(ip: [16]u8) bool {
    return std.mem.allEqual(u8, ip[0..10], 0) and ip[10] == 0xff and ip[11] == 0xff;
}

test "ssrf: blocks private IPv4 by default" {
    try std.testing.expect(!isAllowedAddress(try std.net.Address.parseIp("10.0.0.1", 80), false));
    try std.testing.expect(!isAllowedAddress(try std.net.Address.parseIp("172.16.0.1", 80), false));
    try std.testing.expect(!isAllowedAddress(try std.net.Address.parseIp("192.168.1.1", 80), false));
    try std.testing.expect(!isAllowedAddress(try std.net.Address.parseIp("127.0.0.1", 80), false));
    try std.testing.expect(!isAllowedAddress(try std.net.Address.parseIp("169.254.1.1", 80), false));
    try std.testing.expect(isAllowedAddress(try std.net.Address.parseIp("8.8.8.8", 80), false));
}

test "ssrf: allow_private enables private ranges but still blocks multicast and unspecified" {
    try std.testing.expect(isAllowedAddress(try std.net.Address.parseIp("10.0.0.1", 80), true));
    try std.testing.expect(isAllowedAddress(try std.net.Address.parseIp("127.0.0.1", 80), true));
    try std.testing.expect(!isAllowedAddress(try std.net.Address.parseIp("0.0.0.0", 80), true));
    try std.testing.expect(!isAllowedAddress(try std.net.Address.parseIp("224.0.0.1", 80), true));
}

test "ssrf: blocks private IPv6 by default" {
    try std.testing.expect(!isAllowedAddress(try std.net.Address.parseIp("::1", 80), false));
    try std.testing.expect(!isAllowedAddress(try std.net.Address.parseIp("fc00::1", 80), false));
    try std.testing.expect(!isAllowedAddress(try std.net.Address.parseIp("fe80::1", 80), false));
    try std.testing.expect(isAllowedAddress(try std.net.Address.parseIp("2001:4860:4860::8888", 80), false));
}

test "ssrf: blocks IPv4-mapped IPv6 using IPv4 rules" {
    try std.testing.expect(!isAllowedAddress(try std.net.Address.parseIp("::ffff:127.0.0.1", 80), false));
    try std.testing.expect(isAllowedAddress(try std.net.Address.parseIp("::ffff:8.8.8.8", 80), false));
}
