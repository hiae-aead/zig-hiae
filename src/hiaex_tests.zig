const std = @import("std");
const HiaeX = @import("hiaex.zig").HiaeX;

pub const Hiae = HiaeX(1);
pub const HiaeX2 = HiaeX(2);
pub const HiaeX4 = HiaeX(4);

test "HiaeX round trip" {
    const io = std.Io.Threaded.global_single_threaded.io();
    var random_source = std.Random.IoSource{ .io = io };
    const random = random_source.interface();

    var key: [32]u8 = undefined;
    var nonce: [16]u8 = undefined;
    var ad_buf: [1024]u8 = undefined;
    var plaintext_buf: [1024]u8 = undefined;
    var decrypted_buf: [1024]u8 = undefined;
    var ciphertext_buf: [1024]u8 = undefined;

    const Variants: [3]type = .{ Hiae, HiaeX2, HiaeX4 };
    inline for (Variants) |Variant| {
        for (0..1000) |_| {
            const ad_len = random.uintAtMost(usize, ad_buf.len);
            const plaintext_len = random.uintAtMost(usize, plaintext_buf.len);
            const decrypted_len = plaintext_len;
            const ciphertext_len = plaintext_len;
            const ad = ad_buf[0..ad_len];
            const plaintext = plaintext_buf[0..plaintext_len];
            const decrypted = decrypted_buf[0..decrypted_len];
            const ciphertext = ciphertext_buf[0..ciphertext_len];

            random.bytes(&key);
            random.bytes(&nonce);
            random.bytes(ad);
            random.bytes(plaintext);
            const tag = Variant.encrypt(ciphertext, plaintext, ad, key, nonce);
            try Variant.decrypt(decrypted, ciphertext, tag, ad, key, nonce);
            try std.testing.expectEqualSlices(u8, plaintext, decrypted);
        }
    }
}
