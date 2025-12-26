const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main executable (CLI)
    const exe = b.addExecutable(.{
        .name = "axiom",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/axiom-cli.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    // Add src/ to include path for stub headers
    exe.root_module.addIncludePath(b.path("src"));

    // Link against libzfs
    exe.root_module.linkSystemLibrary("zfs", .{});
    exe.root_module.linkSystemLibrary("nvpair", .{});
    exe.root_module.linkSystemLibrary("zfs_core", .{});

    b.installArtifact(exe);

    // Manifest parser test executable
    const test_manifest = b.addExecutable(.{
        .name = "test-manifest",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test-manifest.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    b.installArtifact(test_manifest);

    // Package store test executable
    const test_store = b.addExecutable(.{
        .name = "test-store",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test-store.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    test_store.root_module.addIncludePath(b.path("src"));
    test_store.root_module.linkSystemLibrary("zfs", .{});
    test_store.root_module.linkSystemLibrary("nvpair", .{});
    test_store.root_module.linkSystemLibrary("zfs_core", .{});
    b.installArtifact(test_store);

    // Profile management test executable
    const test_profile = b.addExecutable(.{
        .name = "test-profile",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test-profile.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    test_profile.root_module.addIncludePath(b.path("src"));
    test_profile.root_module.linkSystemLibrary("zfs", .{});
    test_profile.root_module.linkSystemLibrary("nvpair", .{});
    test_profile.root_module.linkSystemLibrary("zfs_core", .{});
    b.installArtifact(test_profile);

    // Dependency resolver test executable
    const test_resolver = b.addExecutable(.{
        .name = "test-resolver",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test-resolver.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    test_resolver.root_module.addIncludePath(b.path("src"));
    test_resolver.root_module.linkSystemLibrary("zfs", .{});
    test_resolver.root_module.linkSystemLibrary("nvpair", .{});
    test_resolver.root_module.linkSystemLibrary("zfs_core", .{});
    b.installArtifact(test_resolver);

    // Realization engine test executable
    const test_realization = b.addExecutable(.{
        .name = "test-realization",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test-realization.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    test_realization.root_module.addIncludePath(b.path("src"));
    test_realization.root_module.linkSystemLibrary("zfs", .{});
    test_realization.root_module.linkSystemLibrary("nvpair", .{});
    test_realization.root_module.linkSystemLibrary("zfs_core", .{});
    b.installArtifact(test_realization);

    // ZFS integration test executable (original main.zig)
    const zfs_test = b.addExecutable(.{
        .name = "zfs-test",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    zfs_test.root_module.addIncludePath(b.path("src"));
    zfs_test.root_module.linkSystemLibrary("zfs", .{});
    zfs_test.root_module.linkSystemLibrary("nvpair", .{});
    zfs_test.root_module.linkSystemLibrary("zfs_core", .{});
    b.installArtifact(zfs_test);

    // Garbage collector test executable
    const test_gc = b.addExecutable(.{
        .name = "test-gc",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test-gc.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    test_gc.root_module.addIncludePath(b.path("src"));
    test_gc.root_module.linkSystemLibrary("zfs", .{});
    test_gc.root_module.linkSystemLibrary("nvpair", .{});
    test_gc.root_module.linkSystemLibrary("zfs_core", .{});
    b.installArtifact(test_gc);

    // Import test executable
    const test_import = b.addExecutable(.{
        .name = "test-import",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test-import.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    test_import.root_module.addIncludePath(b.path("src"));
    test_import.root_module.linkSystemLibrary("zfs", .{});
    test_import.root_module.linkSystemLibrary("nvpair", .{});
    test_import.root_module.linkSystemLibrary("zfs_core", .{});
    b.installArtifact(test_import);

    // Signature test executable
    const test_signature = b.addExecutable(.{
        .name = "test-signature",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test-signature.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    test_signature.root_module.addIncludePath(b.path("src"));
    b.installArtifact(test_signature);

    // Cache test executable
    const test_cache = b.addExecutable(.{
        .name = "test-cache",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test-cache.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    test_cache.root_module.addIncludePath(b.path("src"));
    test_cache.root_module.linkSystemLibrary("zfs", .{});
    test_cache.root_module.linkSystemLibrary("nvpair", .{});
    test_cache.root_module.linkSystemLibrary("zfs_core", .{});
    b.installArtifact(test_cache);

    // Run command
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // ==================== Unit Tests ====================

    // ZFS module unit tests
    const zfs_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/zfs.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    zfs_tests.root_module.addIncludePath(b.path("src"));
    zfs_tests.root_module.linkSystemLibrary("zfs", .{});
    zfs_tests.root_module.linkSystemLibrary("nvpair", .{});
    zfs_tests.root_module.linkSystemLibrary("zfs_core", .{});

    // Types module unit tests (version constraints, etc.)
    const types_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/types.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    // Manifest module unit tests
    const manifest_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/manifest.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    // Resolver module unit tests
    const resolver_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/resolver.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    resolver_tests.root_module.addIncludePath(b.path("src"));
    resolver_tests.root_module.linkSystemLibrary("zfs", .{});
    resolver_tests.root_module.linkSystemLibrary("nvpair", .{});
    resolver_tests.root_module.linkSystemLibrary("zfs_core", .{});

    // Signature module unit tests (no ZFS needed)
    const signature_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/signature.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    // ==================== Test Steps ====================

    // Basic test step (unit tests only, no root required)
    const run_zfs_tests = b.addRunArtifact(zfs_tests);
    const run_types_tests = b.addRunArtifact(types_tests);
    const run_manifest_tests = b.addRunArtifact(manifest_tests);
    const run_resolver_tests = b.addRunArtifact(resolver_tests);
    const run_signature_tests = b.addRunArtifact(signature_tests);

    const test_step = b.step("test", "Run unit tests (no root required)");
    test_step.dependOn(&run_types_tests.step);
    test_step.dependOn(&run_manifest_tests.step);
    test_step.dependOn(&run_signature_tests.step);

    // Full test step (includes ZFS tests, requires root)
    const test_full_step = b.step("test-full", "Run all unit tests (requires root for ZFS)");
    test_full_step.dependOn(&run_types_tests.step);
    test_full_step.dependOn(&run_manifest_tests.step);
    test_full_step.dependOn(&run_signature_tests.step);
    test_full_step.dependOn(&run_resolver_tests.step);
    test_full_step.dependOn(&run_zfs_tests.step);

    // ==================== CI Step ====================
    const ci_step = b.step("ci", "Run CI test suite (build + unit tests)");
    ci_step.dependOn(b.getInstallStep());
    ci_step.dependOn(&run_types_tests.step);
    ci_step.dependOn(&run_manifest_tests.step);
    ci_step.dependOn(&run_signature_tests.step);
    const run_test_manifest_exe = b.addRunArtifact(test_manifest);
    ci_step.dependOn(&run_test_manifest_exe.step);

    // ==================== CI-Full Step ====================
    const ci_full_step = b.step("ci-full", "Run full CI suite (requires root + ZFS)");
    ci_full_step.dependOn(b.getInstallStep());
    ci_full_step.dependOn(&run_types_tests.step);
    ci_full_step.dependOn(&run_manifest_tests.step);
    ci_full_step.dependOn(&run_signature_tests.step);
    ci_full_step.dependOn(&run_resolver_tests.step);
    ci_full_step.dependOn(&run_zfs_tests.step);
    const run_test_store_exe = b.addRunArtifact(test_store);
    const run_test_gc_exe = b.addRunArtifact(test_gc);
    const run_test_import_exe = b.addRunArtifact(test_import);
    const run_test_signature_exe = b.addRunArtifact(test_signature);
    ci_full_step.dependOn(&run_test_manifest_exe.step);
    ci_full_step.dependOn(&run_test_store_exe.step);
    ci_full_step.dependOn(&run_test_gc_exe.step);
    ci_full_step.dependOn(&run_test_import_exe.step);
    ci_full_step.dependOn(&run_test_signature_exe.step);

    // ==================== Check Step ====================
    const check_step = b.step("check", "Check compilation without running tests");
    check_step.dependOn(&exe.step);
    check_step.dependOn(&test_manifest.step);
    check_step.dependOn(&test_store.step);
    check_step.dependOn(&test_profile.step);
    check_step.dependOn(&test_resolver.step);
    check_step.dependOn(&test_realization.step);
    check_step.dependOn(&test_gc.step);
    check_step.dependOn(&test_import.step);
    check_step.dependOn(&test_signature.step);
    check_step.dependOn(&test_cache.step);
    check_step.dependOn(&zfs_test.step);
}
