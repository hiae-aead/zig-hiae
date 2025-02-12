const std = @import("std");
const mem = std.mem;
const random = std.crypto.random;
const time = std.time;
const Timer = std.time.Timer;

const hiae = @import("lib.zig");

const msg_len: usize = 16384;
const iterations = 100000;

pub const std_options = std.Options{ .side_channels_mitigations = .none };

fn benchHiae(comptime desc: []const u8, comptime Aead: type) !void {
    var key: [Aead.key_length]u8 = undefined;
    var nonce: [Aead.nonce_length]u8 = undefined;
    var buf: [msg_len + Aead.tag_length]u8 = undefined;
    const ad = [_]u8{};

    random.bytes(&key);
    random.bytes(&nonce);
    random.bytes(&buf);

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..iterations) |_| {
        const tag = Aead.encrypt(&buf, &buf, &ad, key, nonce);
        buf[0] ^= tag[0];
    }
    const end = timer.read();
    mem.doNotOptimizeAway(buf[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000_000_000)));
    const stdout = std.io.getStdOut().writer();
    try stdout.print("{s}\t{d:10.1} Gb/s\n", .{ desc, throughput });
}

fn benchHiaeMac(desc: []const u8, comptime Aead: type) !void {
    var key: [Aead.key_length]u8 = undefined;
    var nonce: [Aead.nonce_length]u8 = undefined;
    var data: [msg_len]u8 = undefined;

    random.bytes(&key);
    random.bytes(&nonce);
    random.bytes(&data);

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..iterations) |_| {
        const tag = Aead.mac(&data, key, nonce);
        data[0] ^= tag[0];
    }
    const end = timer.read();
    mem.doNotOptimizeAway(data[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000_000_000)));
    const stdout = std.io.getStdOut().writer();
    try stdout.print("{s}\t{d:10.1} Gb/s\n", .{ desc, throughput });
}

fn benchLeMac() !void {
    const LeMac = @import("lemac/lemac.zig").LeMac;

    var key: [LeMac.key_len]u8 = undefined;
    var nonce: [LeMac.nonce_len]u8 = undefined;
    var data: [msg_len]u8 = undefined;

    random.bytes(&key);
    random.bytes(&nonce);
    random.bytes(&data);

    const st = LeMac.init(key);

    var timer = try Timer.start();
    const start = timer.lap();
    for (0..iterations) |_| {
        const tag = st.mac(&data, nonce);
        data[0] ^= tag[0];
    }
    const end = timer.read();
    mem.doNotOptimizeAway(data[0]);
    const bits: f128 = @floatFromInt(@as(u128, msg_len) * iterations * 8);
    const elapsed_s = @as(f128, @floatFromInt(end - start)) / time.ns_per_s;
    const throughput = @as(f64, @floatCast(bits / (elapsed_s * 1000_000_000)));
    const stdout = std.io.getStdOut().writer();
    try stdout.print("LeMAC\t{d:10.1} Gb/s\n", .{throughput});
}

pub fn main() !void {
    try benchHiae("HiAE", hiae.Hiae);
    try benchHiae("HiAEX2", hiae.HiaeX2);
    try benchHiae("HiAEX4", hiae.HiaeX4);

    try benchHiaeMac("HiAE-MAC", hiae.Hiae);
    try benchHiaeMac("HiAEX2-MAC", hiae.HiaeX2);
    try benchHiaeMac("HiAEX4-MAC", hiae.HiaeX4);
    try benchLeMac();
}
