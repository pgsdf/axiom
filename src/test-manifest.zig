const std = @import("std");
const manifest = @import("manifest.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Axiom Manifest Parser - Phase 2 Test\n", .{});
    std.debug.print("====================================\n\n", .{});

    // Test manifest.yaml parsing
    const manifest_content = try std.fs.cwd().readFileAlloc(
        allocator,
        "examples/manifest.yaml",
        1024 * 1024,
    );
    defer allocator.free(manifest_content);

    std.debug.print("Parsing manifest.yaml...\n", .{});
    var pkg_manifest = try manifest.Manifest.parse(allocator, manifest_content);
    defer pkg_manifest.deinit(allocator);

    try pkg_manifest.validate();

    std.debug.print("  Name: {s}\n", .{pkg_manifest.name});
    std.debug.print("  Version: {f}\n", .{pkg_manifest.version});
    std.debug.print("  Revision: {d}\n", .{pkg_manifest.revision});
    if (pkg_manifest.description) |desc| {
        std.debug.print("  Description: {s}\n", .{desc});
    }
    if (pkg_manifest.license) |lic| {
        std.debug.print("  License: {s}\n", .{lic});
    }
    if (pkg_manifest.tags.len > 0) {
        std.debug.print("  Tags: ", .{});
        for (pkg_manifest.tags, 0..) |tag, i| {
            if (i > 0) std.debug.print(", ", .{});
            std.debug.print("{s}", .{tag});
        }
        std.debug.print("\n", .{});
    }

    // Test deps.yaml parsing
    std.debug.print("\nParsing deps.yaml...\n", .{});
    const deps_content = try std.fs.cwd().readFileAlloc(
        allocator,
        "examples/deps.yaml",
        1024 * 1024,
    );
    defer allocator.free(deps_content);

    var deps_manifest = try manifest.DependencyManifest.parse(allocator, deps_content);
    defer deps_manifest.deinit(allocator);

    std.debug.print("  Dependencies ({d}):\n", .{deps_manifest.dependencies.len});
    for (deps_manifest.dependencies) |dep| {
        std.debug.print("    - {s}: ", .{dep.name});
        switch (dep.constraint) {
            .exact => |v| std.debug.print("={f}\n", .{v}),
            .tilde => |v| std.debug.print("~{f}\n", .{v}),
            .caret => |v| std.debug.print("^{f}\n", .{v}),
            .any => std.debug.print("*\n", .{}),
            .range => |r| {
                if (r.min) |min| {
                    std.debug.print("{s}{f}", .{ if (r.min_inclusive) ">=" else ">", min });
                }
                if (r.max) |max| {
                    if (r.min != null) std.debug.print(",", .{});
                    std.debug.print("{s}{f}", .{ if (r.max_inclusive) "<=" else "<", max });
                }
                std.debug.print("\n", .{});
            },
        }
    }

    // Test provenance.yaml parsing
    std.debug.print("\nParsing provenance.yaml...\n", .{});
    const prov_content = try std.fs.cwd().readFileAlloc(
        allocator,
        "examples/provenance.yaml",
        1024 * 1024,
    );
    defer allocator.free(prov_content);

    var prov_manifest = try manifest.Provenance.parse(allocator, prov_content);
    defer prov_manifest.deinit(allocator);

    std.debug.print("  Build Time: {d}\n", .{prov_manifest.build_time});
    std.debug.print("  Builder: {s}\n", .{prov_manifest.builder});
    if (prov_manifest.compiler) |c| {
        std.debug.print("  Compiler: {s}", .{c});
        if (prov_manifest.compiler_version) |v| {
            std.debug.print(" {s}", .{v});
        }
        std.debug.print("\n", .{});
    }
    if (prov_manifest.build_flags.len > 0) {
        std.debug.print("  Build Flags:\n", .{});
        for (prov_manifest.build_flags) |flag| {
            std.debug.print("    {s}\n", .{flag});
        }
    }

    std.debug.print("\n✓ All manifests parsed successfully!\n", .{});
}
