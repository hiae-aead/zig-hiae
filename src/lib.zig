const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const AesBlockVec = crypto.core.aes.BlockVec;
const AuthenticationError = std.crypto.errors.AuthenticationError;

pub const Hiae = HiaeX(1);
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
            self.s[0] = self.s[0].xorBlocks(k0_v);
            self.s[7] = self.s[7].xorBlocks(k1_v);

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
