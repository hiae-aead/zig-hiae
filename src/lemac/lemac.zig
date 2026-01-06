const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const AesBlock = crypto.core.aes.Block;
const Aes128 = crypto.core.aes.Aes128;
const AesEncryptCtx = crypto.core.aes.AesEncryptCtx(Aes128);

// https://tosc.iacr.org/index.php/ToSC/article/view/11619/11111

pub const LeMac = struct {
    pub const key_len = 16;
    pub const nonce_len = 16;
    pub const tag_len = 16;

    aes_k2_ctx: AesEncryptCtx,
    aes_k3_ctx: AesEncryptCtx,
    k_init: [9][16]u8,
    k_final: [18][16]u8,

    pub fn init(key: [16]u8) LeMac {
        // Key derivation
        var k_init: [9][16]u8 = undefined;
        for (&k_init, 0..) |*a, i| {
            mem.writeInt(u128, a, i, .little);
        }
        var k_final: [18][16]u8 = undefined;
        for (&k_final, 9..) |*a, i| {
            mem.writeInt(u128, a, i, .little);
        }
        const aes_ctx = Aes128.initEnc(key);
        aes_ctx.encryptWide(k_init.len, @ptrCast(&k_init), @ptrCast(&k_init));
        aes_ctx.encryptWide(k_final.len, @ptrCast(&k_final), @ptrCast(&k_final));

        // Key schedule for k2 and k3
        var k2_k3: [16 * 2]u8 = undefined;
        mem.writeInt(u128, k2_k3[0..16], 27, .little);
        mem.writeInt(u128, k2_k3[16..32], 28, .little);
        aes_ctx.encryptWide(2, &k2_k3, &k2_k3);
        const aes_k2_ctx = Aes128.initEnc(k2_k3[0..16].*);
        const aes_k3_ctx = Aes128.initEnc(k2_k3[16..32].*);

        return LeMac{
            .aes_k2_ctx = aes_k2_ctx,
            .aes_k3_ctx = aes_k3_ctx,
            .k_init = k_init,
            .k_final = k_final,
        };
    }

    pub fn mac(self: *const LeMac, msg: []const u8, nonce: [16]u8) [16]u8 {
        const zeroblock = AesBlock.fromBytes(&([_]u8{0} ** 16));

        // UHF
        var x: [9]AesBlock = undefined;
        for (&x, self.k_init) |*a, b| {
            a.* = AesBlock.fromBytes(&b);
        }
        var r: [3]AesBlock = undefined;
        for (&r) |*a| {
            a.* = zeroblock;
        }
        var rr = zeroblock;
        var i: usize = 0;
        while (i + 64 <= msg.len) : (i += 64) {
            const m0 = AesBlock.fromBytes(msg[i + 16 * 0 ..][0..16]);
            const m1 = AesBlock.fromBytes(msg[i + 16 * 1 ..][0..16]);
            const m2 = AesBlock.fromBytes(msg[i + 16 * 2 ..][0..16]);
            const m3 = AesBlock.fromBytes(msg[i + 16 * 3 ..][0..16]);
            const tmp = x[8];
            x[8] = x[7].encrypt(m3);
            x[7] = x[6].encrypt(m1);
            x[6] = x[5].encrypt(m1);
            x[5] = x[4].encrypt(m0);
            x[4] = x[3].encrypt(m0);
            x[3] = x[2].encrypt(r[1]).xorBlocks(r[2]);
            x[2] = x[1].encrypt(m3);
            x[1] = x[0].encrypt(m3);
            x[0] = x[0].xorBlocks(tmp).xorBlocks(m2);
            r[2] = r[1];
            r[1] = r[0];
            r[0] = rr.xorBlocks(m1);
            rr = m2;
        }
        const left = msg.len - i;
        var pad = [_]u8{0} ** 64;
        @memcpy(pad[0..left], msg[i..]);
        pad[left] = 0x80;
        {
            const m0 = AesBlock.fromBytes(pad[16 * 0 ..][0..16]);
            const m1 = AesBlock.fromBytes(pad[16 * 1 ..][0..16]);
            const m2 = AesBlock.fromBytes(pad[16 * 2 ..][0..16]);
            const m3 = AesBlock.fromBytes(pad[16 * 3 ..][0..16]);
            const tmp = x[8];
            x[8] = x[7].encrypt(m3);
            x[7] = x[6].encrypt(m1);
            x[6] = x[5].encrypt(m1);
            x[5] = x[4].encrypt(m0);
            x[4] = x[3].encrypt(m0);
            x[3] = x[2].encrypt(r[1]).xorBlocks(r[2]);
            x[2] = x[1].encrypt(m3);
            x[1] = x[0].encrypt(m3);
            x[0] = x[0].xorBlocks(tmp).xorBlocks(m2);
            r[2] = r[1];
            r[1] = r[0];
            r[0] = rr.xorBlocks(m1);
            rr = m2;
        }

        // Finalization

        for (0..4) |_| {
            const tmp = x[8];
            x[8] = x[7].encrypt(zeroblock);
            x[7] = x[6].encrypt(zeroblock);
            x[6] = x[5].encrypt(zeroblock);
            x[5] = x[4].encrypt(zeroblock);
            x[4] = x[3].encrypt(zeroblock);
            x[3] = x[2].encrypt(r[1]).xorBlocks(r[2]);
            x[2] = x[1].encrypt(zeroblock);
            x[1] = x[0].encrypt(zeroblock);
            x[0] = x[0].xorBlocks(tmp);
            r[2] = r[1];
            r[1] = r[0];
            r[0] = rr;
            rr = zeroblock;
        }

        for (0..10) |round| {
            for (&x, 0..) |*a, j| {
                a.* = a.*.xorBlocks(AesBlock.fromBytes(&self.k_final[round + j])).encrypt(zeroblock);
            }
        }
        var h = x[0];
        for (x[1..]) |a| {
            h = h.xorBlocks(a);
        }

        // EWCDM
        var enc_n: [16]u8 = undefined;
        self.aes_k2_ctx.encrypt(&enc_n, &nonce);
        var h_bytes = h.toBytes();
        for (&h_bytes, nonce, enc_n) |*a, b, c| {
            a.* ^= b ^ c;
        }
        var tag: [16]u8 = undefined;
        self.aes_k3_ctx.encrypt(&tag, &h_bytes);

        return tag;
    }
};

test {
    const key: [16]u8 = [_]u8{ 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    const nonce: [16]u8 = [_]u8{0} ** 16;
    const msg = [_]u8{0x02} ** 100;
    const expected_tag: [16]u8 = [_]u8{ 221, 165, 166, 236, 201, 150, 215, 101, 227, 154, 25, 74, 2, 162, 227, 115 };
    const st = LeMac.init(key);
    const tag: [16]u8 = st.mac(&msg, nonce);
    try std.testing.expectEqualSlices(u8, &expected_tag, &tag);
}
