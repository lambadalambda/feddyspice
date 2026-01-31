const std = @import("std");
const feddyspice = @import("feddyspice");

pub fn main() !void {
    const address = try std.net.Address.parseIp("0.0.0.0", 8080);
    try feddyspice.server.serve(address);
}
