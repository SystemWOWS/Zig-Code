const std = @import("std");
const build_impl = @import("buildforapi.zig");

pub fn build(b: *std.Build) void {
    build_impl.build(b);
}
