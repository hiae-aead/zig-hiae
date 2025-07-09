//! Simple HiAE implementation without parallelism.

const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const AesBlock = crypto.core.aes.Block;
const AuthenticationError = std.crypto.errors.AuthenticationError;

const Self = @This();

pub const key_length = 32;
pub const nonce_length = 16;
pub const tag_length = 16;
pub const ad_max_length = 1 << 61;
pub const msg_max_length = 1 << 61;
pub const ct_max_length = msg_max_length + tag_length;

const block_length = AesBlock.block_length;
const rate = block_length * 16;

const State = [16]AesBlock;

s: State,

inline fn aesround(in: AesBlock, rk: AesBlock) AesBlock {
    return in.encrypt(rk);
}

inline fn rol(self: *Self) void {
    const s = &self.s;
    const t = s[0];
    inline for (0..s.len - 1) |i| s[i] = s[i + 1];
    s[s.len - 1] = t;
}

inline fn round(self: *Self, comptime i: u4, a: AesBlock) void {
    const s = &self.s;
    const t = aesround(s[0 +% i].xorBlocks(s[1 +% i]), a);
    s[0 +% i] = aesround(s[13 +% i], t);
    s[3 +% i] = s[3 +% i].xorBlocks(a);
    s[13 +% i] = s[13 +% i].xorBlocks(a);
}

inline fn eRound(self: *Self, comptime i: u4, m: AesBlock) AesBlock {
    const s = &self.s;
    const t = aesround(s[0 +% i].xorBlocks(s[1 +% i]), m);
    const c = t.xorBlocks(s[9 +% i]);
    s[0 +% i] = aesround(s[13 +% i], t);
    s[3 +% i] = s[3 +% i].xorBlocks(m);
    s[13 +% i] = s[13 +% i].xorBlocks(m);
    return c;
}

inline fn dRound(self: *Self, comptime i: u4, c: AesBlock) AesBlock {
    const s = &self.s;
    const t = c.xorBlocks(s[9 +% i]);
    const m = aesround(s[0 +% i].xorBlocks(s[1 +% i]), t);
    s[0 +% i] = aesround(s[13 +% i], t);
    s[3 +% i] = s[3 +% i].xorBlocks(m);
    s[13 +% i] = s[13 +% i].xorBlocks(m);
    return m;
}

inline fn diffusionRounds(self: *Self, m: AesBlock) void {
    @setEvalBranchQuota(10000);
    const s = &self.s;
    for (0..2) |_| {
        inline for (0..s.len) |i| {
            self.round(@intCast(i), m);
        }
    }
}

fn absorb(self: *Self, ai: *const [rate]u8) void {
    @setEvalBranchQuota(10000);
    const s = &self.s;
    inline for (0..s.len) |i| {
        const m = AesBlock.fromBytes(ai[i * block_length ..][0..block_length]);
        self.round(@intCast(i), m);
    }
}

fn absorbOne(self: *Self, ai: *const [block_length]u8) void {
    const m = AesBlock.fromBytes(ai);
    self.round(0, m);
    self.rol();
}

fn encBatch(self: *Self, ci: *[rate]u8, mi: *const [rate]u8) void {
    @setEvalBranchQuota(10000);
    const s = &self.s;
    inline for (0..s.len) |i| {
        const m = AesBlock.fromBytes(mi[i * block_length ..][0..block_length]);
        ci[i * block_length ..][0..block_length].* = self.eRound(@intCast(i), m).toBytes();
    }
}

fn encOne(self: *Self, ci: *[block_length]u8, mi: *const [block_length]u8) void {
    const m = AesBlock.fromBytes(mi);
    ci.* = self.eRound(0, m).toBytes();
    self.rol();
}

fn decBatch(self: *Self, mi: *[rate]u8, ci: *const [rate]u8) void {
    @setEvalBranchQuota(10000);
    const s = &self.s;
    inline for (0..s.len) |i| {
        const c = AesBlock.fromBytes(ci[i * block_length ..][0..block_length]);
        const m = self.dRound(@intCast(i), c);
        mi[i * block_length ..][0..block_length].* = m.toBytes();
    }
}

fn decOne(self: *Self, mi: *[block_length]u8, ci: *const [block_length]u8) void {
    const c = AesBlock.fromBytes(ci);
    const m = self.dRound(0, c);
    mi.* = m.toBytes();
    self.rol();
}

fn decLast(self: *Self, mi: []u8, ci: []const u8) void {
    const s = &self.s;
    var c_padded = [_]u8{0} ** block_length;
    @memcpy(c_padded[0..ci.len], ci);
    const ks = aesround(s[0].xorBlocks(s[1]), AesBlock.fromBytes(&c_padded)).xorBlocks(s[9]);
    const ks_bytes = ks.toBytes();
    @memcpy(c_padded[ci.len..], ks_bytes[ci.len..]);
    const c = AesBlock.fromBytes(&c_padded);
    const m = self.dRound(0, c);
    const m_bytes = m.toBytes();
    @memcpy(mi, m_bytes[0..mi.len]);
    self.rol();
}

fn init(key: [key_length]u8, nonce: [nonce_length]u8) Self {
    const c0_v = AesBlock.fromBytes(&[16]u8{ 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 });
    const c1_v = AesBlock.fromBytes(&[16]u8{ 0x4a, 0x40, 0x93, 0x82, 0x22, 0x99, 0xf3, 0x1d, 0x00, 0x82, 0xef, 0xa9, 0x8e, 0xc4, 0xe6, 0xc8 });
    const k0_v = AesBlock.fromBytes(&key[0..16].*);
    const k1_v = AesBlock.fromBytes(&key[16..].*);
    const nonce_v = AesBlock.fromBytes(&nonce);
    const zero_v = AesBlock.fromBytes(&[_]u8{0x00} ** 16);
    var self = Self{ .s = State{
        c0_v,                    k1_v,                    nonce_v, c0_v,
        zero_v,                  nonce_v.xorBlocks(k0_v), zero_v,  c1_v,
        nonce_v.xorBlocks(k1_v), zero_v,                  k1_v,    c0_v,
        c1_v,                    k1_v,                    zero_v,  c0_v.xorBlocks(c1_v),
    } };
    self.diffusionRounds(c0_v);
    self.s[9] = self.s[9].xorBlocks(k0_v);
    self.s[13] = self.s[13].xorBlocks(k1_v);

    return self;
}

fn finalize(self: *Self, ad_len: usize, msg_len: usize) [tag_length]u8 {
    var s = &self.s;
    var b: [block_length]u8 = undefined;
    mem.writeInt(u64, b[0..8], @as(u64, ad_len) * 8, .little);
    mem.writeInt(u64, b[8..16], @as(u64, msg_len) * 8, .little);
    const t = AesBlock.fromBytes(&b);
    self.diffusionRounds(t);
    var tag = s[0];
    for (s[1..]) |x| tag = tag.xorBlocks(x);
    return tag.toBytes();
}

fn finalizeMac(self: *Self, data_len: usize) [tag_length]u8 {
    return self.finalize(data_len, 0);
}

pub fn encrypt(
    ct: []u8,
    msg: []const u8,
    ad: []const u8,
    key: [key_length]u8,
    nonce: [nonce_length]u8,
) [tag_length]u8 {
    assert(msg.len <= msg_max_length);
    assert(ad.len <= ad_max_length);
    assert(ct.len == msg.len);

    var hiae = init(key, nonce);

    var i: usize = 0;
    while (i + rate <= ad.len) : (i += rate) {
        hiae.absorb(ad[i..][0..rate]);
    }
    while (i + block_length <= ad.len) : (i += block_length) {
        hiae.absorbOne(ad[i..][0..block_length]);
    }
    const left = ad.len % block_length;
    if (left > 0) {
        var pad = [_]u8{0} ** block_length;
        @memcpy(pad[0..left], ad[i..]);
        hiae.absorbOne(&pad);
    }

    i = 0;
    while (i + rate <= msg.len) : (i += rate) {
        hiae.encBatch(ct[i..][0..rate], msg[i..][0..rate]);
    }
    while (i + block_length <= msg.len) : (i += block_length) {
        hiae.encOne(ct[i..][0..block_length], msg[i..][0..block_length]);
    }
    if (msg.len % block_length > 0) {
        var pad = [_]u8{0} ** block_length;
        @memcpy(pad[0..msg[i..].len], msg[i..]);
        hiae.encOne(&pad, &pad);
        @memcpy(ct[i..], pad[0..ct[i..].len]);
    }

    return hiae.finalize(ad.len, msg.len);
}

pub fn decrypt(
    msg: []u8,
    ct: []const u8,
    tag: [tag_length]u8,
    ad: []const u8,
    key: [key_length]u8,
    nonce: [nonce_length]u8,
) AuthenticationError!void {
    assert(ct.len <= ct_max_length);
    assert(ad.len <= ad_max_length);
    assert(ct.len == msg.len);
    var hiae = init(key, nonce);

    var i: usize = 0;
    while (i + rate <= ad.len) : (i += rate) {
        hiae.absorb(ad[i..][0..rate]);
    }
    while (i + block_length <= ad.len) : (i += block_length) {
        hiae.absorbOne(ad[i..][0..block_length]);
    }
    const left = ad.len % block_length;
    if (left > 0) {
        var pad = [_]u8{0} ** block_length;
        @memcpy(pad[0..left], ad[i..]);
        hiae.absorbOne(&pad);
    }

    i = 0;
    while (i + rate <= ct.len) : (i += rate) {
        hiae.decBatch(msg[i..][0..rate], ct[i..][0..rate]);
    }
    while (i + block_length <= ct.len) : (i += block_length) {
        hiae.decOne(msg[i..][0..block_length], ct[i..][0..block_length]);
    }
    if (ct.len % block_length > 0) {
        hiae.decLast(msg[i..], ct[i..]);
    }

    const expected_tag = hiae.finalize(ad.len, msg.len);
    if (!crypto.utils.timingSafeEql([expected_tag.len]u8, expected_tag, tag)) {
        crypto.utils.secureZero(u8, msg);
        return error.AuthenticationFailed;
    }
}

pub fn mac(
    data: []const u8,
    key: [key_length]u8,
    nonce: [nonce_length]u8,
) [tag_length]u8 {
    assert(data.len <= ad_max_length);
    var hiae = init(key, nonce);

    var i: usize = 0;
    while (i + rate <= data.len) : (i += rate) {
        hiae.absorb(data[i..][0..rate]);
    }
    while (i + block_length <= data.len) : (i += block_length) {
        hiae.absorbOne(data[i..][0..block_length]);
    }
    const left = data.len % block_length;
    if (left > 0) {
        var pad = [_]u8{0} ** block_length;
        @memcpy(pad[0..left], data[i..]);
        hiae.absorbOne(&pad);
    }
    return hiae.finalizeMac(data.len);
}
