pub const Hiae = @import("hiae.zig");

const HiaeX = @import("hiaex.zig").HiaeX;
pub const HiaeX2 = HiaeX(2);
pub const HiaeX4 = HiaeX(4);

test {
    _ = @import("hiae_tests.zig");
    _ = @import("hiaex_tests.zig");
}
