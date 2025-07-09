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
            .name = "Test Vector 1 - Empty plaintext, no AD",
            .key_hex = "4b7a9c3ef8d2165a0b3e5f8c9d4a7b1e2c5f8a9d3b6e4c7f0a1d2e5b8c9f4a7d",
            .nonce_hex = "a5b8c2d9e3f4a7b1c8d5e9f2a3b6c7d8",
            .ad_hex = "",
            .plaintext_hex = "",
            .ciphertext_hex = "",
            .tag_hex = "e3b7c5993e804d7e1f95905fe8fa1d74",
        },
        TestVector{
            .name = "Test Vector 2 - Single block plaintext, no AD",
            .key_hex = "2f8e4d7c3b9a5e1f8d2c6b4a9f3e7d5c1b8a6f4e3d2c9b5a8f7e6d4c3b2a1f9e",
            .nonce_hex = "7c3e9f5a1d8b4c6f2e9a5d7b3f8c1e4a",
            .ad_hex = "",
            .plaintext_hex = "55f00fcc339669aa55f00fcc339669aa",
            .ciphertext_hex = "66fc201d96ace3ca550326964c2fa950",
            .tag_hex = "2e4d9b3bf320283de63ea5547454878d",
        },
        TestVector{
            .name = "Test Vector 3 - Empty plaintext with AD",
            .key_hex = "9f3e7d5c4b8a2f1e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e",
            .nonce_hex = "3d8c7f2a5b9e4c1f8a6d3b7e5c2f9a4d",
            .ad_hex = "394a5b6c7d8e9fb0c1d2e3f405162738495a6b7c8d9eafc0d1e2f30415263748",
            .plaintext_hex = "",
            .ciphertext_hex = "",
            .tag_hex = "531a4d1ed47bda55d01cc510512099e4",
        },
        TestVector{
            .name = "Test Vector 4 - Rate-aligned plaintext (256 bytes)",
            .key_hex = "6c8f2d5a9e3b7f4c1d8a5e9f3c7b2d6a4f8e1c9b5d3a7e2f4c8b6d9a1e5f3c7d",
            .nonce_hex = "9a5c7e3f1b8d4a6c2e9f5b7d3a8c1e6f",
            .ad_hex = "",
            .plaintext_hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            .ciphertext_hex = "2e28f49c20d1a90a5bce3bc85f6eab2fe0d3ee31c293f368ee20e485ec732c9045633aa4d53e271b1f583f4f0b2084876e4b0d2b2f633433e43c48386155d03d00dbf10c07a66159e1bec7859839263ac12e77045c6d718ddf5907297818e4ae0b4ed7b890f57fa585e4a5940525aa2f62e4b6748fa4cd86b75f69eff9dfd4df9b0861ae7d52541ff892aa41d41d55a9a62f4e4fefb718ee13faca582d73c1d1f51592c25c64b0a79d2f24181362dfbb352ac20e1b07be892a05b394eb6b2a9d473c49e6b63e754311fdbb6c476503f0a3570482ece70856ae6e6f8d5aa19cc27b5bce24ee028e197ed9891b0a54bf02328cb80ceefc44b11043d784594226ab",
            .tag_hex = "f330ae219d6739aba556fe94776b486b",
        },
        TestVector{
            .name = "Test Vector 5 - Rate + 1 byte plaintext",
            .key_hex = "3e9d6c5b4a8f7e2d1c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d",
            .nonce_hex = "6f2e8a5c9b3d7f1e4a8c5b9d3f7e2a6c",
            .ad_hex = "6778899aabbccddeef00112233445566",
            .plaintext_hex = "cc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc",
            .ciphertext_hex = "5d2d2c7f1ff780687c65ed69c08805c269652b55f5d1ef005f25300d1f644b57e500d5b0d75f9b025fee04cfdf422c6c3c472e6967ac60f69ff730d4d308faedbeac375ae88da8ab78d26e496a5226b5ffd7834a2f76ecc495a444ffa3db60d8ec3fb75c0fcaa74966e1caec294c8eb7a4895aa2b1e3976eb6bed2f975ff218dc98f86f7c95996f03842cee71c6c1bc5f7b64374e101b32927ed95432e88f8e38835f1981325dbcec412a4254e964c22cf82688ee5e471c23a3537de7e51c28892e32c565aa86ab708c70cf01f0d0ee9781251759893d55e60e0d70014cb3afb45e0821ba6e82e0f490ff2efef2f62c57332c68c11e6ed71ef730b62c3e05edff6",
            .tag_hex = "1122dc5bedc7cad4e196f7227b7102f3",
        },
        TestVector{
            .name = "Test Vector 6 - Rate - 1 byte plaintext",
            .key_hex = "8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f",
            .nonce_hex = "4d8b2f6a9c3e7f5d1b8a4c6e9f3d5b7a",
            .ad_hex = "",
            .plaintext_hex = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            .ciphertext_hex = "322970ad70b2af87676d57dd0b27866d8c4f0e251b5162b93672de1ab7aaf20cd91e7751a31e19762aeea4f3811657a306787ff4ebc06957c1f45b7fd284ef87f3a902922999895ff26fddbd5986eac5ef856f6ae270136315c698ec7fe5a6188aa1847c00a3a870044e8d37e22b1bcab3e493d8ae984c7646f2536032a40910b6c0f317b916d5789189268c00ef4493bcb5fb0135974fa9bec299d473fdbf76f44107ec56b5941404fd4b3352576c313169662f1664bd5bccf210a710aa6665fb3ec4fa3b4c648411fd09d4cada31b8947fdd486de45a4e4a33c151364e23be6b3fc14f0855b0518e733d5ea905116525286bb2d6a46ac8ef73144e2046f9",
            .tag_hex = "7eb4461a035fe51eaf4a1829605e6227",
        },
        TestVector{
            .name = "Test Vector 7 - Medium plaintext with AD",
            .key_hex = "5d9c3b7a8f2e6d4c1b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c",
            .nonce_hex = "8c5a7d3f9b1e6c4a2f8d5b9e3c7a1f6d",
            .ad_hex = "95a6b7c8d9eafb0c1d2e3f5061728394a5b6c7d8e9fa0b1c2d3e4f60718293a4b5c6d7e8f90a1b2c3d4e5f708192a3b4c5d6e7f8091a2b3c4d5e6f8091a2b3c4",
            .plaintext_hex = "32e14453e7a776781d4c4e2c3b23bca2441ee4213bc3df25021b5106c22c98e8a7b310142252c8dcff70a91d55cdc9103c1eccd9b5309ef21793a664e0d4b63c83530dcd1a6ad0feda6ff19153e9ee620325c1cb979d7b32e54f41da3af1c169a24c47c1f6673e115f0cb73e8c507f15eedf155261962f2d175c9ba3832f4933fb330d28ad6aae787f12788706f45c92e72aea146959d2d4fa01869f7d072a7bf43b2e75265e1a000dde451b64658919e93143d2781955fb4ca2a38076ac9eb49adc2b92b05f0ec7",
            .ciphertext_hex = "ca3b18f0ffb25e4e1a6108abedcfc931841804c22a132a701d2f0b5eb845a3808028e9e1e0978795776c57a0415971cfe87abc72171a24fd11f3c331d1efe306e4ca1d8ede6e79cbd531020502d3802620d9453ffdd5633fe98ff1d12b057eddbd4d99ee6cabf4c8d2c9b4c7ee0d219b3b4145e3c63acde6c45f6d65e08dd06ef9dd2dde090f1f7579a5657720f348ae5761a8df321f20ad711a2c703b1c3f200e4004da409daaa138f3c20f8f77c89cb6f46df671f25c75a6a7838a5d792d18a59c202fab564f0f",
            .tag_hex = "74ba4c28296f09101db59c37c4759bcf",
        },
        TestVector{
            .name = "Test Vector 8 - Single byte plaintext",
            .key_hex = "7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a",
            .nonce_hex = "2e7c9f5d3b8a4c6f1e9b5d7a3f8c2e4a",
            .ad_hex = "",
            .plaintext_hex = "ff",
            .ciphertext_hex = "51",
            .tag_hex = "588535eb70c53ba5cce0d215194cb1c9",
        },
        TestVector{
            .name = "Test Vector 9 - Two blocks plaintext",
            .key_hex = "4c8b7a9f3e5d2c6b1a8f9e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b",
            .nonce_hex = "7e3c9a5f1d8b4e6c2a9f5d7b3e8c1a4f",
            .ad_hex = "c3d4e5f60718293a4b5c6d7e8fa0b1c2d3e4f5061728394a5b6c7d8e9fb0c1d2e3f405162738495a6b7c8d9eafc0d1e2",
            .plaintext_hex = "aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669aa55f00fcc339669",
            .ciphertext_hex = "03694107097ff7ea0b1eac408fabb60acd89df4d0288fa9063309e5e323bf78f",
            .tag_hex = "2a3144f369a893c3d756f262067e5e59",
        },
        TestVector{
            .name = "Test Vector 10 - All zeros plaintext",
            .key_hex = "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d",
            .nonce_hex = "5f9d3b7e2c8a4f6d1b9e5c7a3d8f2b6e",
            .ad_hex = "daebfc0d1e2f405162738495a6b7c8d9",
            .plaintext_hex = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            .ciphertext_hex = "eef78d00c4de4c557d5c769e499af7b98e5ad36cdaf1ff775a8629d82751e97e8f98caa0773fe81ee40266f0d52ddbbef621504863bf39552682b29748f8c2445c176cd63865732141edc59073cff90e5996a23a763f8dd058a6a91ada1d8f832f5e600b39f799a698228b68d20cd189e5e423b253a44c78060435050698ccae",
            .tag_hex = "59970b0b35a7822f3b88b63396c2da98",
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
