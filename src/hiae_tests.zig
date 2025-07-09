const std = @import("std");
const Hiae = @import("hiae.zig");

test "HiAE test vectors" {
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

        var decrypted_buf: [1024]u8 = undefined;
        var decrypted = decrypted_buf[0..plaintext.len];
        try Hiae.decrypt(decrypted, ciphertext, tag, ad, key, nonce);
        try std.testing.expectEqualSlices(u8, plaintext[0..], decrypted[0..]);
    }
}
