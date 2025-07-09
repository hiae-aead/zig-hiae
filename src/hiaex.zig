//! HiAE ipmlementation with support for parallelism.
//! Note that when degree=1, this is equivalent to the HiAE implementation in `hiae.zig`.

const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const mem = std.mem;
const AesBlockVec = crypto.core.aes.BlockVec;
const AuthenticationError = std.crypto.errors.AuthenticationError;

pub fn HiaeX(comptime degree: u7) type {
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

        inline fn update(self: *Self, comptime i: u4, a: AesBlockX) void {
            const s = &self.s;
            const t = aesround(s[0 +% i].xorBlocks(s[1 +% i]), a);
            s[0 +% i] = aesround(s[13 +% i], t);
            s[3 +% i] = s[3 +% i].xorBlocks(a);
            s[13 +% i] = s[13 +% i].xorBlocks(a);
        }

        inline fn updateEnc(self: *Self, comptime i: u4, m: AesBlockX) AesBlockX {
            const s = &self.s;
            const t = aesround(s[0 +% i].xorBlocks(s[1 +% i]), m);
            const c = t.xorBlocks(s[9 +% i]);
            s[0 +% i] = aesround(s[13 +% i], t);
            s[3 +% i] = s[3 +% i].xorBlocks(m);
            s[13 +% i] = s[13 +% i].xorBlocks(m);
            return c;
        }

        inline fn updateDec(self: *Self, comptime i: u4, c: AesBlockX) AesBlockX {
            const s = &self.s;
            const t = c.xorBlocks(s[9 +% i]);
            const m = aesround(s[0 +% i].xorBlocks(s[1 +% i]), t);
            s[0 +% i] = aesround(s[13 +% i], t);
            s[3 +% i] = s[3 +% i].xorBlocks(m);
            s[13 +% i] = s[13 +% i].xorBlocks(m);
            return m;
        }

        inline fn diffusionRounds(self: *Self, m: AesBlockX) void {
            @setEvalBranchQuota(10000);
            const s = &self.s;
            for (0..2) |_| {
                inline for (0..s.len) |i| {
                    self.update(@intCast(i), m);
                }
            }
        }

        fn absorbBatch(self: *Self, ai: *const [rate]u8) void {
            @setEvalBranchQuota(10000);
            const s = &self.s;
            inline for (0..s.len) |i| {
                const m = AesBlockX.fromBytes(ai[i * blockx_length ..][0..blockx_length]);
                self.update(@intCast(i), m);
            }
        }

        fn absorb(self: *Self, ai: *const [blockx_length]u8) void {
            const m = AesBlockX.fromBytes(ai);
            self.update(0, m);
            self.rol();
        }

        fn encBatch(self: *Self, ci: *[rate]u8, mi: *const [rate]u8) void {
            @setEvalBranchQuota(10000);
            const s = &self.s;
            inline for (0..s.len) |i| {
                const m = AesBlockX.fromBytes(mi[i * blockx_length ..][0..blockx_length]);
                ci[i * blockx_length ..][0..blockx_length].* = self.updateEnc(@intCast(i), m).toBytes();
            }
        }

        fn enc(self: *Self, ci: *[blockx_length]u8, mi: *const [blockx_length]u8) void {
            const m = AesBlockX.fromBytes(mi);
            ci.* = self.updateEnc(0, m).toBytes();
            self.rol();
        }

        fn decBatch(self: *Self, mi: *[rate]u8, ci: *const [rate]u8) void {
            @setEvalBranchQuota(10000);
            const s = &self.s;
            inline for (0..s.len) |i| {
                const c = AesBlockX.fromBytes(ci[i * blockx_length ..][0..blockx_length]);
                const m = self.updateDec(@intCast(i), c);
                mi[i * blockx_length ..][0..blockx_length].* = m.toBytes();
            }
        }

        fn dec(self: *Self, mi: *[blockx_length]u8, ci: *const [blockx_length]u8) void {
            const c = AesBlockX.fromBytes(ci);
            const m = self.updateDec(0, c);
            self.rol();
            mi.* = m.toBytes();
        }

        fn decPartial(self: *Self, mi: []u8, ci: []const u8) void {
            const s = &self.s;
            var c_padded = [_]u8{0} ** blockx_length;
            @memcpy(c_padded[0..ci.len], ci);
            const ks = aesround(s[0].xorBlocks(s[1]), AesBlockX.fromBytes(&c_padded)).xorBlocks(s[9]);
            const ks_bytes = ks.toBytes();
            @memcpy(c_padded[ci.len..], ks_bytes[ci.len..]);
            const c = AesBlockX.fromBytes(&c_padded);
            const m = self.updateDec(0, c);
            self.rol();
            const m_bytes = m.toBytes();
            @memcpy(mi, m_bytes[0..mi.len]);
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
            self.diffusionRounds(c0_v);
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
            self.diffusionRounds(t);
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
            self.diffusionRounds(AesBlockX.fromBytes(&b));
            var tag_multi = s[0];
            for (s[1..]) |x| tag_multi = tag_multi.xorBlocks(x);
            const tag_multi_bytes = tag_multi.toBytes();
            var v = [_]u8{0} ** blockx_length;
            for (1..degree) |d| {
                v[0..16].* = tag_multi_bytes[d * 16 ..][0..16].*;
                self.absorb(&v);
            }
            if (degree > 1) {
                mem.writeInt(u64, b[0..8], degree, .little);
                mem.writeInt(u64, b[8..16], tag_length * 8, .little);
                self.diffusionRounds(AesBlockX.fromBytes(&b));
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
                hiae.absorbBatch(ad[i..][0..rate]);
            }
            while (i + blockx_length <= ad.len) : (i += blockx_length) {
                hiae.absorb(ad[i..][0..blockx_length]);
            }
            const left = ad.len % blockx_length;
            if (left > 0) {
                var pad = [_]u8{0} ** blockx_length;
                @memcpy(pad[0..left], ad[i..]);
                hiae.absorb(&pad);
            }

            i = 0;
            while (i + rate <= msg.len) : (i += rate) {
                hiae.encBatch(ct[i..][0..rate], msg[i..][0..rate]);
            }
            while (i + blockx_length <= msg.len) : (i += blockx_length) {
                hiae.enc(ct[i..][0..blockx_length], msg[i..][0..blockx_length]);
            }
            if (msg.len % blockx_length > 0) {
                var pad = [_]u8{0} ** blockx_length;
                @memcpy(pad[0..msg[i..].len], msg[i..]);
                hiae.enc(&pad, &pad);
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
                hiae.absorbBatch(ad[i..][0..rate]);
            }
            while (i + blockx_length <= ad.len) : (i += blockx_length) {
                hiae.absorb(ad[i..][0..blockx_length]);
            }
            const left = ad.len % blockx_length;
            if (left > 0) {
                var pad = [_]u8{0} ** blockx_length;
                @memcpy(pad[0..left], ad[i..]);
                hiae.absorb(&pad);
            }

            i = 0;
            while (i + rate <= ct.len) : (i += rate) {
                hiae.decBatch(msg[i..][0..rate], ct[i..][0..rate]);
            }
            while (i + blockx_length <= ct.len) : (i += blockx_length) {
                hiae.dec(msg[i..][0..blockx_length], ct[i..][0..blockx_length]);
            }
            if (ct.len % blockx_length > 0) {
                hiae.decPartial(msg[i..], ct[i..]);
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
                hiae.absorbBatch(data[i..][0..rate]);
            }
            while (i + blockx_length <= data.len) : (i += blockx_length) {
                hiae.absorb(data[i..][0..blockx_length]);
            }
            const left = data.len % blockx_length;
            if (left > 0) {
                var pad = [_]u8{0} ** blockx_length;
                @memcpy(pad[0..left], data[i..]);
                hiae.absorb(&pad);
            }
            return hiae.finalizeMac(data.len);
        }
    };
}
