const std = @import("std");

pub fn build(b: *std.Build) void {
    // [TODO 6] Default to ReleaseSmall and strip debug sections so the build
    // doesn't ship DWARF/PDB data that CAPA pattern-matches on. Override with
    // -Doptimize=Debug / -Doptimize=ReleaseFast on the CLI if needed.
    const optimize = b.option(
        std.builtin.OptimizeMode,
        "optimize",
        "Prioritize performance, safety, or binary size",
    ) orelse .ReleaseSmall;
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86_64,
            .os_tag = .windows,
            .abi = .gnu,
        },
    });

    const root_module = b.createModule(.{
        .root_source_file = b.path("API_Hooking.zig"),
        .target = target,
        .optimize = optimize,
        .strip = true,
    });

    const exe = b.addExecutable(.{
        .name = "Api_Hooking",
        .root_module = root_module,
    });

    b.installArtifact(exe);
}
