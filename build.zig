const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main executable (CLI)
    const exe = b.addExecutable(.{
        .name = "axiom",
        .root_source_file = b.path("src/axiom-cli.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Add src/ to include path for stub headers
    exe.addIncludePath(b.path("src"));

    // Link against libc and libzfs
    exe.linkLibC();
    exe.linkSystemLibrary("zfs");
    exe.linkSystemLibrary("nvpair");
    exe.linkSystemLibrary("zfs_core");

    b.installArtifact(exe);

    // Manifest parser test executable
    const test_manifest = b.addExecutable(.{
        .name = "test-manifest",
        .root_source_file = b.path("src/test-manifest.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(test_manifest);

    // Package store test executable
    const test_store = b.addExecutable(.{
        .name = "test-store",
        .root_source_file = b.path("src/test-store.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_store.addIncludePath(b.path("src"));
    test_store.linkLibC();
    test_store.linkSystemLibrary("zfs");
    test_store.linkSystemLibrary("nvpair");
    test_store.linkSystemLibrary("zfs_core");
    b.installArtifact(test_store);

    // Profile management test executable
    const test_profile = b.addExecutable(.{
        .name = "test-profile",
        .root_source_file = b.path("src/test-profile.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_profile.addIncludePath(b.path("src"));
    test_profile.linkLibC();
    test_profile.linkSystemLibrary("zfs");
    test_profile.linkSystemLibrary("nvpair");
    test_profile.linkSystemLibrary("zfs_core");
    b.installArtifact(test_profile);

    // Dependency resolver test executable
    const test_resolver = b.addExecutable(.{
        .name = "test-resolver",
        .root_source_file = b.path("src/test-resolver.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_resolver.addIncludePath(b.path("src"));
    test_resolver.linkLibC();
    test_resolver.linkSystemLibrary("zfs");
    test_resolver.linkSystemLibrary("nvpair");
    test_resolver.linkSystemLibrary("zfs_core");
    b.installArtifact(test_resolver);

    // Realization engine test executable
    const test_realization = b.addExecutable(.{
        .name = "test-realization",
        .root_source_file = b.path("src/test-realization.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_realization.addIncludePath(b.path("src"));
    test_realization.linkLibC();
    test_realization.linkSystemLibrary("zfs");
    test_realization.linkSystemLibrary("nvpair");
    test_realization.linkSystemLibrary("zfs_core");
    b.installArtifact(test_realization);

    // ZFS integration test executable (original main.zig)
    const zfs_test = b.addExecutable(.{
        .name = "zfs-test",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    zfs_test.addIncludePath(b.path("src"));
    zfs_test.linkLibC();
    zfs_test.linkSystemLibrary("zfs");
    zfs_test.linkSystemLibrary("nvpair");
    zfs_test.linkSystemLibrary("zfs_core");
    b.installArtifact(zfs_test);

    // Garbage collector test executable
    const test_gc = b.addExecutable(.{
        .name = "test-gc",
        .root_source_file = b.path("src/test-gc.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_gc.addIncludePath(b.path("src"));
    test_gc.linkLibC();
    test_gc.linkSystemLibrary("zfs");
    test_gc.linkSystemLibrary("nvpair");
    test_gc.linkSystemLibrary("zfs_core");
    b.installArtifact(test_gc);

    // Import test executable
    const test_import = b.addExecutable(.{
        .name = "test-import",
        .root_source_file = b.path("src/test-import.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_import.addIncludePath(b.path("src"));
    test_import.linkLibC();
    test_import.linkSystemLibrary("zfs");
    test_import.linkSystemLibrary("nvpair");
    test_import.linkSystemLibrary("zfs_core");
    b.installArtifact(test_import);

    // Signature test executable
    const test_signature = b.addExecutable(.{
        .name = "test-signature",
        .root_source_file = b.path("src/test-signature.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_signature.addIncludePath(b.path("src"));
    test_signature.linkLibC();
    b.installArtifact(test_signature);

    // Cache test executable
    const test_cache = b.addExecutable(.{
        .name = "test-cache",
        .root_source_file = b.path("src/test-cache.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_cache.addIncludePath(b.path("src"));
    test_cache.linkLibC();
    test_cache.linkSystemLibrary("zfs");
    test_cache.linkSystemLibrary("nvpair");
    test_cache.linkSystemLibrary("zfs_core");
    b.installArtifact(test_cache);

    // Run command
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Tests
    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/zfs.zig"),
        .target = target,
        .optimize = optimize,
    });
    unit_tests.addIncludePath(b.path("src"));
    unit_tests.linkLibC();
    unit_tests.linkSystemLibrary("zfs");
    unit_tests.linkSystemLibrary("nvpair");
    unit_tests.linkSystemLibrary("zfs_core");

    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
