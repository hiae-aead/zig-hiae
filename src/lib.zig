const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const AesBlock = crypto.core.aes.Block;
const AesBlockVec = crypto.core.aes.BlockVec;
const AuthenticationError = std.crypto.errors.AuthenticationError;

pub const HiaeX2 = HiaeX(2);
pub const HiaeX4 = HiaeX(4);

fn HiaeX(comptime degree: u7) type {
    assert(degree > 0); // degree can't be 0

    return struct {
        const Self = @This();

        pub const key_length = 32;
        pub const nonce_length = 16;
        pub const tag_length = 16;
        pub const ad_max_length = 1 << 61;
        pub const msg_max_length = 1 << 61;
        pub const ct_max_length = msg_max_length + tag_length;

        const AesBlockX = AesBlockVec(degree);
        const blockx_length = AesBlockX.block_length;
        const rate = blockx_length * 16;

        const State = [16]AesBlockX;

        s: State,

        inline fn aesround(in: AesBlockX, rk: AesBlockX) AesBlockX {
            return in.encrypt(rk);
        }

        inline fn rol(self: *Self) void {
            const s = &self.s;
            const t = s[0];
            inline for (0..s.len - 1) |i| s[i] = s[i + 1];
            s[s.len - 1] = t;
        }

        inline fn truncateBlock(x: *AesBlockX, len: usize) void {
            var pad = [_]u8{0} ** blockx_length;
            @memcpy(pad[0..len], x.toBytes()[0..len]);
            x.* = AesBlockX.fromBytes(&pad);
        }

        inline fn absorbBroadcast(self: *Self, m: AesBlockX) void {
            @setEvalBranchQuota(10000);
            const s = &self.s;
            for (0..2) |_| {
                inline for (0..s.len) |i_| {
                    const i: u4 = @intCast(i_);
                    const t = aesround(s[0 +% i].xorBlocks(s[1 +% i]), m);
                    s[0 +% i] = aesround(s[13 +% i], t);
                    s[3 +% i] = s[3 +% i].xorBlocks(m);
                    s[13 +% i] = s[13 +% i].xorBlocks(m);
                }
            }
        }

        fn absorb(self: *Self, ai: *const [rate]u8) void {
            @setEvalBranchQuota(10000);
            const s = &self.s;
            inline for (0..s.len) |i_| {
                const i: u4 = @intCast(i_);
                const m = AesBlockX.fromBytes(ai[i * blockx_length ..][0..blockx_length]);
                const t = aesround(s[0 +% i].xorBlocks(s[1 +% i]), m);
                s[0 +% i] = aesround(s[13 +% i], t);
                s[3 +% i] = s[3 +% i].xorBlocks(m);
                s[13 +% i] = s[13 +% i].xorBlocks(m);
            }
        }

        fn absorbOne(self: *Self, ai: *const [blockx_length]u8) void {
            const s = &self.s;
            const m = AesBlockX.fromBytes(ai);
            const t = aesround(s[0].xorBlocks(s[1]), m);
            s[0] = aesround(s[13], t);
            s[3] = s[3].xorBlocks(m);
            s[13] = s[13].xorBlocks(m);
            self.rol();
        }

        fn enc(self: *Self, ci: *[rate]u8, mi: *const [rate]u8) void {
            @setEvalBranchQuota(10000);
            const s = &self.s;
            inline for (0..s.len) |i_| {
                const i: u4 = @intCast(i_);
                const m = AesBlockX.fromBytes(mi[i * blockx_length ..][0..blockx_length]);
                const t = aesround(s[0 +% i].xorBlocks(s[1 +% i]), m);
                s[0 +% i] = aesround(s[13 +% i], t);
                s[3 +% i] = s[3 +% i].xorBlocks(m);
                s[13 +% i] = s[13 +% i].xorBlocks(m);
                ci[i * blockx_length ..][0..blockx_length].* = s[9 +% i].xorBlocks(t).toBytes();
            }
        }

        fn encOne(self: *Self, ci: *[blockx_length]u8, mi: *const [blockx_length]u8) void {
            const s = &self.s;
            const m = AesBlockX.fromBytes(mi);
            const t = aesround(s[0].xorBlocks(s[1]), m);
            s[0] = aesround(s[13], t);
            s[3] = s[3].xorBlocks(m);
            s[13] = s[13].xorBlocks(m);
            ci.* = s[9].xorBlocks(t).toBytes();
            self.rol();
        }

        fn encLast(self: *Self, ci: []u8, mi: []const u8) void {
            const s = &self.s;
            var pad = [_]u8{0} ** blockx_length;
            @memcpy(pad[0..mi.len], mi);
            const m = AesBlockX.fromBytes(&pad);
            var t = aesround(s[0].xorBlocks(s[1]), m);
            truncateBlock(&t, mi.len);
            s[0] = aesround(s[13], t);
            s[3] = s[3].xorBlocks(m);
            s[13] = s[13].xorBlocks(m);
            const c = s[9].xorBlocks(t);
            @memcpy(ci, c.toBytes()[0..ci.len]);
            self.rol();
        }

        fn dec(self: *Self, mi: *[rate]u8, ci: *const [rate]u8) void {
            @setEvalBranchQuota(10000);
            const s = &self.s;
            inline for (0..s.len) |i_| {
                const i: u4 = @intCast(i_);
                const c = AesBlockX.fromBytes(ci[i * blockx_length ..][0..blockx_length]);
                const t = s[9 +% i].xorBlocks(c);
                const m = aesround(s[0 +% i].xorBlocks(s[1 +% i]), t);
                s[0 +% i] = aesround(s[13 +% i], t);
                s[3 +% i] = s[3 +% i].xorBlocks(m);
                s[13 +% i] = s[13 +% i].xorBlocks(m);
                mi[i * blockx_length ..][0..blockx_length].* = m.toBytes();
            }
        }

        fn decOne(self: *Self, mi: *[blockx_length]u8, ci: *const [blockx_length]u8) void {
            const s = &self.s;
            const c = AesBlockX.fromBytes(ci);
            const t = s[9].xorBlocks(c);
            const m = aesround(s[0].xorBlocks(s[1]), t);
            s[0] = aesround(s[13], t);
            s[3] = s[3].xorBlocks(m);
            s[13] = s[13].xorBlocks(m);
            mi.* = m.toBytes();
            self.rol();
        }

        fn decLast(self: *Self, mi: []u8, ci: []const u8) void {
            const s = &self.s;
            var pad = [_]u8{0} ** blockx_length;
            @memcpy(pad[0..ci.len], ci);
            const c = AesBlockX.fromBytes(&pad);
            var t = s[9].xorBlocks(c);
            truncateBlock(&t, ci.len);
            var m = aesround(s[0].xorBlocks(s[1]), t);
            truncateBlock(&m, ci.len);
            s[0] = aesround(s[13], t);
            s[3] = s[3].xorBlocks(m);
            s[13] = s[13].xorBlocks(m);
            @memcpy(mi, m.toBytes()[0..mi.len]);
            self.rol();
        }

        fn init(key: [key_length]u8, nonce: [nonce_length]u8) Self {
            const c0_v = AesBlockX.fromBytes(&[16]u8{ 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 } ** degree);
            const c1_v = AesBlockX.fromBytes(&[16]u8{ 0x4a, 0x40, 0x93, 0x82, 0x22, 0x99, 0xf3, 0x1d, 0x00, 0x82, 0xef, 0xa9, 0x8e, 0xc4, 0xe6, 0xc8 } ** degree);
            const k0_v = AesBlockX.fromBytes(&(key[0..16].* ** degree));
            const k1_v = AesBlockX.fromBytes(&(key[16..].* ** degree));
            const nonce_v = AesBlockX.fromBytes(&(nonce ** degree));
            const zero_v = AesBlockX.fromBytes(&[_]u8{0x00} ** (16 * degree));
            const ctx_v = ctx_v: {
                var contexts_bytes = [_]u8{0} ** blockx_length;
                for (0..degree) |i| {
                    contexts_bytes[i * 16] = @intCast(i);
                    contexts_bytes[i * 16 + 1] = @intCast(degree - 1);
                }
                break :ctx_v AesBlockX.fromBytes(&contexts_bytes);
            };
            var self = Self{ .s = State{
                c0_v,                    k1_v,                    nonce_v, c0_v,
                zero_v,                  nonce_v.xorBlocks(k0_v), zero_v,  c1_v,
                nonce_v.xorBlocks(k1_v), zero_v,                  k1_v,    c0_v,
                c1_v,                    k1_v,                    zero_v,  c0_v.xorBlocks(c1_v),
            } };
            if (degree > 1) {
                for (&self.s) |*x| x.* = x.*.xorBlocks(ctx_v);
            }
            self.absorbBroadcast(c0_v);
            self.s[9] = self.s[9].xorBlocks(k0_v);
            self.s[13] = self.s[13].xorBlocks(k1_v);

            return self;
        }

        fn finalize(self: *Self, ad_len: usize, msg_len: usize) [tag_length]u8 {
            var s = &self.s;
            var b: [blockx_length]u8 = undefined;
            mem.writeInt(u64, b[0..8], @as(u64, ad_len) * 8, .little);
            mem.writeInt(u64, b[8..16], @as(u64, msg_len) * 8, .little);
            for (1..degree) |i| {
                b[i * 16 ..][0..16].* = b[0..16].*;
            }
            const t = AesBlockX.fromBytes(&b);
            self.absorbBroadcast(t);
            var tag_multi = s[0];
            for (s[1..]) |x| tag_multi = tag_multi.xorBlocks(x);
            const tag_multi_bytes = tag_multi.toBytes();
            var tag = tag_multi_bytes[0..tag_length].*;
            for (1..degree) |d| {
                for (0..tag_length) |i| {
                    tag[i] ^= tag_multi_bytes[d * tag_length + i];
                }
            }
            return tag;
        }

        fn finalizeMac(self: *Self, data_len: usize) [tag_length]u8 {
            var s = &self.s;
            var b: [blockx_length]u8 = undefined;
            mem.writeInt(u64, b[0..8], @as(u64, data_len) * 8, .little);
            mem.writeInt(u64, b[8..16], tag_length * 8, .little);
            for (1..degree) |i| {
                b[i * 16 ..][0..16].* = b[0..16].*;
            }
            self.absorbBroadcast(AesBlockX.fromBytes(&b));
            var tag_multi = s[0];
            for (s[1..]) |x| tag_multi = tag_multi.xorBlocks(x);
            const tag_multi_bytes = tag_multi.toBytes();
            var v = [_]u8{0} ** blockx_length;
            for (1..degree) |d| {
                v[0..16].* = tag_multi_bytes[d * 16 ..][0..16].*;
                self.absorbOne(&v);
            }
            if (degree > 1) {
                mem.writeInt(u64, b[0..8], degree, .little);
                mem.writeInt(u64, b[8..16], tag_length * 8, .little);
                self.absorbBroadcast(AesBlockX.fromBytes(&b));
            }
            tag_multi = s[0];
            for (s[1..]) |x| tag_multi = tag_multi.xorBlocks(x);
            return tag_multi.toBytes()[0..tag_length].*;
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
            while (i + blockx_length <= ad.len) : (i += blockx_length) {
                hiae.absorbOne(ad[i..][0..blockx_length]);
            }
            const left = ad.len % blockx_length;
            if (left > 0) {
                var pad = [_]u8{0} ** blockx_length;
                @memcpy(pad[0..left], ad[i..]);
                hiae.absorbOne(&pad);
            }

            i = 0;
            while (i + rate <= msg.len) : (i += rate) {
                hiae.enc(ct[i..][0..rate], msg[i..][0..rate]);
            }
            while (i + blockx_length <= msg.len) : (i += blockx_length) {
                hiae.encOne(ct[i..][0..blockx_length], msg[i..][0..blockx_length]);
            }
            if (msg.len % blockx_length > 0) {
                hiae.encLast(ct[i..], msg[i..]);
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
            while (i + blockx_length <= ad.len) : (i += blockx_length) {
                hiae.absorbOne(ad[i..][0..blockx_length]);
            }
            const left = ad.len % blockx_length;
            if (left > 0) {
                var pad = [_]u8{0} ** blockx_length;
                @memcpy(pad[0..left], ad[i..]);
                hiae.absorbOne(&pad);
            }

            i = 0;
            while (i + rate <= ct.len) : (i += rate) {
                hiae.dec(msg[i..][0..rate], ct[i..][0..rate]);
            }
            while (i + blockx_length <= ct.len) : (i += blockx_length) {
                hiae.decOne(msg[i..][0..blockx_length], ct[i..][0..blockx_length]);
            }
            if (ct.len % blockx_length > 0) {
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
            while (i + blockx_length <= data.len) : (i += blockx_length) {
                hiae.absorbOne(data[i..][0..blockx_length]);
            }
            const left = data.len % blockx_length;
            if (left > 0) {
                var pad = [_]u8{0} ** blockx_length;
                @memcpy(pad[0..left], data[i..]);
                hiae.absorbOne(&pad);
            }
            return hiae.finalizeMac(data.len);
        }
    };
}

const Hiae = struct {
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

    inline fn truncateBlock(x: *AesBlock, len: usize) void {
        var pad = [_]u8{0} ** block_length;
        @memcpy(pad[0..len], x.toBytes()[0..len]);
        x.* = AesBlock.fromBytes(&pad);
    }

    inline fn absorbBroadcast(self: *Self, m: AesBlock) void {
        @setEvalBranchQuota(10000);
        const s = &self.s;
        for (0..2) |_| {
            inline for (0..s.len) |i_| {
                const i: u4 = @intCast(i_);
                const t = aesround(s[0 +% i].xorBlocks(s[1 +% i]), m);
                s[0 +% i] = aesround(s[13 +% i], t);
                s[3 +% i] = s[3 +% i].xorBlocks(m);
                s[13 +% i] = s[13 +% i].xorBlocks(m);
            }
        }
    }

    fn absorb(self: *Self, ai: *const [rate]u8) void {
        @setEvalBranchQuota(10000);
        const s = &self.s;
        inline for (0..s.len) |i_| {
            const i: u4 = @intCast(i_);
            const m = AesBlock.fromBytes(ai[i * block_length ..][0..block_length]);
            const t = aesround(s[0 +% i].xorBlocks(s[1 +% i]), m);
            s[0 +% i] = aesround(s[13 +% i], t);
            s[3 +% i] = s[3 +% i].xorBlocks(m);
            s[13 +% i] = s[13 +% i].xorBlocks(m);
        }
    }

    fn absorbOne(self: *Self, ai: *const [block_length]u8) void {
        const s = &self.s;
        const m = AesBlock.fromBytes(ai);
        const t = aesround(s[0].xorBlocks(s[1]), m);
        s[0] = aesround(s[13], t);
        s[3] = s[3].xorBlocks(m);
        s[13] = s[13].xorBlocks(m);
        self.rol();
    }

    fn enc(self: *Self, ci: *[rate]u8, mi: *const [rate]u8) void {
        @setEvalBranchQuota(10000);
        const s = &self.s;
        inline for (0..s.len) |i_| {
            const i: u4 = @intCast(i_);
            const m = AesBlock.fromBytes(mi[i * block_length ..][0..block_length]);
            const t = aesround(s[0 +% i].xorBlocks(s[1 +% i]), m);
            s[0 +% i] = aesround(s[13 +% i], t);
            s[3 +% i] = s[3 +% i].xorBlocks(m);
            s[13 +% i] = s[13 +% i].xorBlocks(m);
            ci[i * block_length ..][0..block_length].* = s[9 +% i].xorBlocks(t).toBytes();
        }
    }

    fn encOne(self: *Self, ci: *[block_length]u8, mi: *const [block_length]u8) void {
        const s = &self.s;
        const m = AesBlock.fromBytes(mi);
        const t = aesround(s[0].xorBlocks(s[1]), m);
        s[0] = aesround(s[13], t);
        s[3] = s[3].xorBlocks(m);
        s[13] = s[13].xorBlocks(m);
        ci.* = s[9].xorBlocks(t).toBytes();
        self.rol();
    }

    fn encLast(self: *Self, ci: []u8, mi: []const u8) void {
        const s = &self.s;
        var pad = [_]u8{0} ** block_length;
        @memcpy(pad[0..mi.len], mi);
        const m = AesBlock.fromBytes(&pad);
        var t = aesround(s[0].xorBlocks(s[1]), m);
        truncateBlock(&t, mi.len);
        s[0] = aesround(s[13], t);
        s[3] = s[3].xorBlocks(m);
        s[13] = s[13].xorBlocks(m);
        const c = s[9].xorBlocks(t);
        @memcpy(ci, c.toBytes()[0..ci.len]);
        self.rol();
    }

    fn dec(self: *Self, mi: *[rate]u8, ci: *const [rate]u8) void {
        @setEvalBranchQuota(10000);
        const s = &self.s;
        inline for (0..s.len) |i_| {
            const i: u4 = @intCast(i_);
            const c = AesBlock.fromBytes(ci[i * block_length ..][0..block_length]);
            const t = s[9 +% i].xorBlocks(c);
            const m = aesround(s[0 +% i].xorBlocks(s[1 +% i]), t);
            s[0 +% i] = aesround(s[13 +% i], t);
            s[3 +% i] = s[3 +% i].xorBlocks(m);
            s[13 +% i] = s[13 +% i].xorBlocks(m);
            mi[i * block_length ..][0..block_length].* = m.toBytes();
        }
    }

    fn decOne(self: *Self, mi: *[block_length]u8, ci: *const [block_length]u8) void {
        const s = &self.s;
        const c = AesBlock.fromBytes(ci);
        const t = s[9].xorBlocks(c);
        const m = aesround(s[0].xorBlocks(s[1]), t);
        s[0] = aesround(s[13], t);
        s[3] = s[3].xorBlocks(m);
        s[13] = s[13].xorBlocks(m);
        mi.* = m.toBytes();
        self.rol();
    }

    fn decLast(self: *Self, mi: []u8, ci: []const u8) void {
        const s = &self.s;
        var pad = [_]u8{0} ** block_length;
        @memcpy(pad[0..ci.len], ci);
        const c = AesBlock.fromBytes(&pad);
        var t = s[9].xorBlocks(c);
        truncateBlock(&t, ci.len);
        var m = aesround(s[0].xorBlocks(s[1]), t);
        truncateBlock(&m, ci.len);
        s[0] = aesround(s[13], t);
        s[3] = s[3].xorBlocks(m);
        s[13] = s[13].xorBlocks(m);
        @memcpy(mi, m.toBytes()[0..mi.len]);
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
        self.absorbBroadcast(c0_v);
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
        self.absorbBroadcast(t);
        var tag = s[0];
        for (s[1..]) |x| tag = tag.xorBlocks(x);
        return tag.toBytes();
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
            hiae.enc(ct[i..][0..rate], msg[i..][0..rate]);
        }
        while (i + block_length <= msg.len) : (i += block_length) {
            hiae.encOne(ct[i..][0..block_length], msg[i..][0..block_length]);
        }
        if (msg.len % block_length > 0) {
            hiae.encLast(ct[i..], msg[i..]);
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
            hiae.dec(msg[i..][0..rate], ct[i..][0..rate]);
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
        return hiae.finalize(data.len, 0);
    }
};

test "test vectors" {
    const TestVector = struct {
        name: []const u8,
        key_hex: *const [2 * 32]u8,
        nonce_hex: *const [2 * 16]u8,
        ad_hex: []const u8,
        plaintext_hex: []const u8,
        ciphertext_hex: []const u8,
        tag_hex: *const [2 * 16]u8,
    };
    const tvs = [_]TestVector{
        TestVector{
            .name = "Test Vector 11",
            .key_hex = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
            .nonce_hex = "381d72b1a195e7f3dc185a35eedb6326",
            .ad_hex = "",
            .plaintext_hex = "",
            .ciphertext_hex = "",
            .tag_hex = "d5057fdfa5a309ce2be6d2651e7232fb",
        },
        TestVector{
            .name = "Test Vector 12",
            .key_hex = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
            .nonce_hex = "381d72b1a195e7f3dc185a35eedb6326",
            .ad_hex = "",
            .plaintext_hex = "9fd7339411b6d56373f4a9697200eeaa",
            .ciphertext_hex = "d716f4983b0025a57cd4c3c3c94a146d",
            .tag_hex = "02a6e6a7267c402a3f625522577efe56",
        },
        TestVector{
            .name = "Test Vector 13",
            .key_hex = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
            .nonce_hex = "381d72b1a195e7f3dc185a35eedb6326",
            .ad_hex = "9fd7339411b6d56373f4a9697200eeaa",
            .plaintext_hex = "",
            .ciphertext_hex = "",
            .tag_hex = "891b7b5e3d8f8ed8e80e2da57af4cb4d",
        },
        TestVector{
            .name = "Test Vector 1",
            .key_hex = "90bbc6ec798423365146306759d6812e37c3740df539834052bd1f46f57d5785",
            .nonce_hex = "381d72b1a195e7f3dc185a35eedb6326",
            .ad_hex = "9fd7339411b6d56373f4a9697200eeaa1d605cbff643b2d25b0c074ae76a708642a31b5359f0b6cde45f36566024017d855d3c7ba0ee4dfcfa5446e2beb66800598353b273097f5869b5aec9daaf465f0c83daad7127a96c7bef4e39a5b63afe",
            .plaintext_hex = "3a8db0ad97300500e5b4c9bf630f1e7092f81d041fc6709ab5bed45a740e58ae9b085c323861321e15fbdd790bfce99df406a114cc11ae81cf82db449033f22c3b4e5e74b09192c58c6f3e976b2735602dd674f9e8227ab7a555fb3588ee61c43cc038ec51cab2dd39f075a518aa054580793f689bb920400f1b769709d75b46",
            .ciphertext_hex = "ff9fcccf03188954a27c74821b76332bd2490761f9d3e3be14613e91ab0af720cc63177cc72a63eea503bed4cb70b0c42d38551b47b7bbda52f23374a4feea06b8b9c9d3c888935e4a78de02ec329bc866053c77fdabe930f273adc0175802ca31b645d1958afc28806843a671347301130d23a94f3adee985fb2e60f0d5d024",
            .tag_hex = "78674481574ba946b2b1e03e0aab2bd5",
        },
    };
    inline for (tvs) |tv| {
        var key: [32]u8 = undefined;
        var nonce: [16]u8 = undefined;
        _ = try std.fmt.hexToBytes(&key, tv.key_hex);
        _ = try std.fmt.hexToBytes(&nonce, tv.nonce_hex);
        var ad_buf: [1024]u8 = undefined;
        const ad = try std.fmt.hexToBytes(&ad_buf, tv.ad_hex);
        var plaintext_buf: [1024]u8 = undefined;
        const plaintext = try std.fmt.hexToBytes(&plaintext_buf, tv.plaintext_hex);
        var expected_ciphertext_buf: [1024]u8 = undefined;
        const expected_ciphertext = try std.fmt.hexToBytes(&expected_ciphertext_buf, tv.ciphertext_hex);
        var ciphertext_buf: [1024]u8 = undefined;
        var ciphertext = ciphertext_buf[0..expected_ciphertext.len];
        var expected_tag: [16]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected_tag, tv.tag_hex);

        const tag = Hiae.encrypt(ciphertext, plaintext, ad, key, nonce);
        try std.testing.expectEqualSlices(u8, expected_ciphertext[0..], ciphertext[0..]);
        try std.testing.expectEqualSlices(u8, expected_tag[0..], tag[0..]);
    }
}
