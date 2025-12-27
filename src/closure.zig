// Dependency Closure Computation
//
// Computes the complete transitive closure of package dependencies,
// enabling self-contained bundles similar to Nix closures or AppImage bundles.

const std = @import("std");
const types = @import("types.zig");
const store = @import("store.zig");
const manifest = @import("manifest.zig");

const Version = types.Version;
const VersionConstraint = types.VersionConstraint;
const PackageId = types.PackageId;
const Dependency = types.Dependency;
const PackageStore = store.PackageStore;
const Manifest = manifest.Manifest;

/// A package in the closure with its full dependency chain
pub const ClosureEntry = struct {
    id: PackageId,
    manifest: Manifest,
    depth: u32, // Distance from root (0 = requested package)
    required_by: []PackageId, // Packages that depend on this one

    pub fn deinit(self: *ClosureEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.required_by);
    }
};

/// Complete dependency closure for a package or set of packages
pub const Closure = struct {
    allocator: std.mem.Allocator,

    /// Root packages (directly requested)
    roots: std.ArrayList(PackageId),

    /// All packages in the closure (including roots)
    entries: std.StringHashMap(ClosureEntry),

    /// Packages in topological order (dependencies before dependents)
    topo_order: std.ArrayList(PackageId),

    /// Total size of all packages in bytes
    total_size: u64,

    /// Blessed base packages that are assumed to exist on the system
    /// These are NOT included in the closure
    base_packages: std.StringHashMap(void),

    pub fn init(allocator: std.mem.Allocator) Closure {
        return .{
            .allocator = allocator,
            .roots = .empty,
            .entries = std.StringHashMap(ClosureEntry).init(allocator),
            .topo_order = .empty,
            .total_size = 0,
            .base_packages = std.StringHashMap(void).init(allocator),
        };
    }

    pub fn deinit(self: *Closure) void {
        self.roots.deinit(self.allocator);

        var entry_iter = self.entries.iterator();
        while (entry_iter.next()) |entry| {
            var e = entry.value_ptr.*;
            e.deinit(self.allocator);
            self.allocator.free(entry.key_ptr.*);
        }
        self.entries.deinit();

        self.topo_order.deinit(self.allocator);
        self.base_packages.deinit();
    }

    /// Get the number of packages in the closure
    pub fn packageCount(self: *const Closure) usize {
        return self.entries.count();
    }

    /// Check if a package is in the closure
    pub fn contains(self: *const Closure, pkg_id: PackageId) bool {
        const key = packageIdToKey(self.allocator, pkg_id) catch return false;
        defer self.allocator.free(key);
        return self.entries.contains(key);
    }

    /// Get all packages as a slice (in topological order)
    pub fn packages(self: *const Closure) []const PackageId {
        return self.topo_order.items;
    }

    /// Check if a package is a base package (excluded from closure)
    pub fn isBasePackage(self: *const Closure, name: []const u8) bool {
        return self.base_packages.contains(name);
    }
};

/// Closure computation engine
pub const ClosureComputer = struct {
    allocator: std.mem.Allocator,
    pkg_store: *PackageStore,

    /// Base packages that are assumed present on the system
    /// These are typically: libc, kernel interfaces, etc.
    base_packages: std.StringHashMap(void),

    pub fn init(allocator: std.mem.Allocator, pkg_store: *PackageStore) ClosureComputer {
        var computer = ClosureComputer{
            .allocator = allocator,
            .pkg_store = pkg_store,
            .base_packages = std.StringHashMap(void).init(allocator),
        };

        // Initialize default base packages
        // These are the "blessed" packages that bundles can assume exist
        computer.addBasePackage("libc") catch {};
        computer.addBasePackage("libm") catch {};
        computer.addBasePackage("libpthread") catch {};
        computer.addBasePackage("libdl") catch {};
        computer.addBasePackage("librt") catch {};
        computer.addBasePackage("ld-linux") catch {};
        computer.addBasePackage("linux-vdso") catch {};

        return computer;
    }

    pub fn deinit(self: *ClosureComputer) void {
        self.base_packages.deinit();
    }

    /// Add a package to the base set (excluded from closures)
    pub fn addBasePackage(self: *ClosureComputer, name: []const u8) !void {
        try self.base_packages.put(name, {});
    }

    /// Remove a package from the base set
    pub fn removeBasePackage(self: *ClosureComputer, name: []const u8) void {
        _ = self.base_packages.remove(name);
    }

    /// Compute the closure for a single package
    pub fn computeForPackage(self: *ClosureComputer, pkg_id: PackageId) !Closure {
        var closure = Closure.init(self.allocator);
        errdefer closure.deinit();

        // Copy base packages to closure
        var base_iter = self.base_packages.iterator();
        while (base_iter.next()) |entry| {
            try closure.base_packages.put(entry.key_ptr.*, {});
        }

        try closure.roots.append(self.allocator, pkg_id);
        try self.computeRecursive(&closure, pkg_id, 0, null);
        try self.computeTopologicalOrder(&closure);

        return closure;
    }

    /// Compute the closure for multiple packages
    pub fn computeForPackages(self: *ClosureComputer, pkg_ids: []const PackageId) !Closure {
        var closure = Closure.init(self.allocator);
        errdefer closure.deinit();

        // Copy base packages to closure
        var base_iter = self.base_packages.iterator();
        while (base_iter.next()) |entry| {
            try closure.base_packages.put(entry.key_ptr.*, {});
        }

        for (pkg_ids) |pkg_id| {
            try closure.roots.append(self.allocator, pkg_id);
            try self.computeRecursive(&closure, pkg_id, 0, null);
        }

        try self.computeTopologicalOrder(&closure);

        return closure;
    }

    fn computeRecursive(
        self: *ClosureComputer,
        closure: *Closure,
        pkg_id: PackageId,
        depth: u32,
        required_by: ?PackageId,
    ) !void {
        // Skip base packages
        if (closure.isBasePackage(pkg_id.name)) {
            return;
        }

        const key = try packageIdToKey(self.allocator, pkg_id);

        // Check if already in closure
        if (closure.entries.getPtr(key)) |existing| {
            // Update required_by if needed
            if (required_by) |req| {
                var new_required = try self.allocator.alloc(PackageId, existing.required_by.len + 1);
                @memcpy(new_required[0..existing.required_by.len], existing.required_by);
                new_required[existing.required_by.len] = req;
                self.allocator.free(existing.required_by);
                existing.required_by = new_required;
            }
            self.allocator.free(key);
            return;
        }

        // Get package metadata
        var pkg_meta = try self.pkg_store.getPackage(pkg_id);
        defer {
            pkg_meta.manifest.deinit(self.allocator);
            self.allocator.free(pkg_meta.dataset_path);
            for (pkg_meta.dependencies) |dep| {
                self.allocator.free(dep.name);
            }
            self.allocator.free(pkg_meta.dependencies);
        }

        // Create required_by array
        var required_by_arr: []PackageId = &[_]PackageId{};
        if (required_by) |req| {
            required_by_arr = try self.allocator.alloc(PackageId, 1);
            required_by_arr[0] = req;
        }

        // Clone the manifest for storage
        const stored_manifest = try cloneManifest(self.allocator, pkg_meta.manifest);

        // Add to closure
        try closure.entries.put(key, .{
            .id = pkg_id,
            .manifest = stored_manifest,
            .depth = depth,
            .required_by = required_by_arr,
        });

        // Recursively process dependencies
        for (pkg_meta.dependencies) |dep| {
            // Find a version that satisfies the constraint
            const dep_id = try self.resolveDependency(dep);
            if (dep_id) |did| {
                try self.computeRecursive(closure, did, depth + 1, pkg_id);
            }
        }
    }

    fn resolveDependency(self: *ClosureComputer, dep: Dependency) !?PackageId {
        // Query store for packages matching this dependency
        const packages = try self.pkg_store.listPackages();

        for (packages) |pkg_id| {
            if (std.mem.eql(u8, pkg_id.name, dep.name)) {
                if (dep.constraint.satisfies(pkg_id.version)) {
                    return pkg_id;
                }
            }
        }

        return null;
    }

    fn computeTopologicalOrder(self: *ClosureComputer, closure: *Closure) !void {
        // Kahn's algorithm for topological sort
        var in_degree = std.StringHashMap(u32).init(self.allocator);
        defer in_degree.deinit();

        // Initialize in-degrees
        var entry_iter = closure.entries.iterator();
        while (entry_iter.next()) |entry| {
            try in_degree.put(entry.key_ptr.*, @intCast(entry.value_ptr.required_by.len));
        }

        // Find all nodes with in-degree 0 (leaf dependencies)
        var queue: std.ArrayList([]const u8) = .empty;
        defer queue.deinit(self.allocator);

        var degree_iter = in_degree.iterator();
        while (degree_iter.next()) |entry| {
            if (entry.value_ptr.* == 0) {
                try queue.append(self.allocator, entry.key_ptr.*);
            }
        }

        // Process queue
        while (queue.items.len > 0) {
            const key = queue.orderedRemove(0);

            if (closure.entries.get(key)) |entry| {
                try closure.topo_order.append(self.allocator, entry.id);

                // Decrease in-degree of packages that depend on this one
                var iter2 = closure.entries.iterator();
                while (iter2.next()) |e| {
                    for (e.value_ptr.required_by) |req| {
                        const req_key = packageIdToKey(self.allocator, req) catch continue;
                        defer self.allocator.free(req_key);

                        if (std.mem.eql(u8, req_key, key)) {
                            if (in_degree.getPtr(e.key_ptr.*)) |deg| {
                                deg.* -= 1;
                                if (deg.* == 0) {
                                    try queue.append(self.allocator, e.key_ptr.*);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
};

/// Helper function to create a unique key for a PackageId
fn packageIdToKey(allocator: std.mem.Allocator, pkg_id: PackageId) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "{s}-{d}.{d}.{d}-r{d}-{s}", .{
        pkg_id.name,
        pkg_id.version.major,
        pkg_id.version.minor,
        pkg_id.version.patch,
        pkg_id.revision,
        pkg_id.build_id,
    });
}

/// Clone a manifest (deep copy)
fn cloneManifest(allocator: std.mem.Allocator, m: Manifest) !Manifest {
    var cloned = Manifest{
        .name = try allocator.dupe(u8, m.name),
        .version = m.version,
        .revision = m.revision,
        .description = if (m.description) |d| try allocator.dupe(u8, d) else null,
        .license = if (m.license) |l| try allocator.dupe(u8, l) else null,
        .homepage = if (m.homepage) |h| try allocator.dupe(u8, h) else null,
        .maintainer = if (m.maintainer) |mt| try allocator.dupe(u8, mt) else null,
        .tags = undefined,
        .provides = undefined,
        .conflicts = undefined,
        .replaces = undefined,
    };

    // Clone tags
    cloned.tags = try allocator.alloc([]const u8, m.tags.len);
    for (m.tags, 0..) |tag, i| {
        cloned.tags[i] = try allocator.dupe(u8, tag);
    }

    // Clone provides
    cloned.provides = try allocator.alloc([]const u8, m.provides.len);
    for (m.provides, 0..) |p, i| {
        cloned.provides[i] = try allocator.dupe(u8, p);
    }

    // Clone conflicts
    cloned.conflicts = try allocator.alloc(manifest.VirtualPackage, m.conflicts.len);
    for (m.conflicts, 0..) |c, i| {
        cloned.conflicts[i] = .{
            .name = try allocator.dupe(u8, c.name),
            .constraint = c.constraint,
        };
    }

    // Clone replaces
    cloned.replaces = try allocator.alloc(manifest.VirtualPackage, m.replaces.len);
    for (m.replaces, 0..) |r, i| {
        cloned.replaces[i] = .{
            .name = try allocator.dupe(u8, r.name),
            .constraint = r.constraint,
        };
    }

    return cloned;
}

/// Closure statistics for display
pub const ClosureStats = struct {
    package_count: usize,
    total_size_bytes: u64,
    max_depth: u32,
    root_count: usize,
    base_excluded_count: usize,
};

/// Get statistics about a closure
pub fn getClosureStats(closure: *const Closure) ClosureStats {
    var max_depth: u32 = 0;
    var entry_iter = closure.entries.iterator();
    while (entry_iter.next()) |entry| {
        if (entry.value_ptr.depth > max_depth) {
            max_depth = entry.value_ptr.depth;
        }
    }

    return .{
        .package_count = closure.entries.count(),
        .total_size_bytes = closure.total_size,
        .max_depth = max_depth,
        .root_count = closure.roots.items.len,
        .base_excluded_count = closure.base_packages.count(),
    };
}

/// Format closure for display
pub fn formatClosure(
    allocator: std.mem.Allocator,
    closure: *const Closure,
    options: FormatOptions,
) ![]const u8 {
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);

    const writer = output.writer(allocator);

    try writer.writeAll("Closure for: ");
    for (closure.roots.items, 0..) |root, i| {
        if (i > 0) try writer.writeAll(", ");
        var buf: [256]u8 = undefined;
        const str = std.fmt.bufPrint(&buf, "{s}@{d}.{d}.{d}", .{
            root.name,
            root.version.major,
            root.version.minor,
            root.version.patch,
        }) catch unreachable;
        try writer.writeAll(str);
    }
    try writer.writeAll("\n\n");

    const stats = getClosureStats(closure);
    try writer.writeAll("Statistics:\n");
    {
        var buf: [64]u8 = undefined;
        const str = std.fmt.bufPrint(&buf, "  Packages: {d}\n", .{stats.package_count}) catch unreachable;
        try writer.writeAll(str);
    }
    {
        var buf: [64]u8 = undefined;
        const str = std.fmt.bufPrint(&buf, "  Max depth: {d}\n", .{stats.max_depth}) catch unreachable;
        try writer.writeAll(str);
    }
    {
        var buf: [64]u8 = undefined;
        const str = std.fmt.bufPrint(&buf, "  Base packages excluded: {d}\n\n", .{stats.base_excluded_count}) catch unreachable;
        try writer.writeAll(str);
    }

    if (options.show_tree) {
        try writer.writeAll("Dependency tree:\n");
        for (closure.roots.items) |root| {
            try formatTreeNode(writer, closure, root, 0, options.max_depth);
        }
    } else {
        try writer.writeAll("Packages (topological order):\n");
        for (closure.topo_order.items) |pkg_id| {
            var buf: [256]u8 = undefined;
            const str = std.fmt.bufPrint(&buf, "  {s}@{d}.{d}.{d}\n", .{
                pkg_id.name,
                pkg_id.version.major,
                pkg_id.version.minor,
                pkg_id.version.patch,
            }) catch unreachable;
            try writer.writeAll(str);
        }
    }

    return try output.toOwnedSlice(allocator);
}

fn formatTreeNode(
    writer: anytype,
    closure: *const Closure,
    pkg_id: PackageId,
    indent: u32,
    max_depth: ?u32,
) !void {
    if (max_depth) |md| {
        if (indent > md) return;
    }

    // Print indent
    var i: u32 = 0;
    while (i < indent) : (i += 1) {
        try writer.writeAll("  ");
    }

    var buf: [256]u8 = undefined;
    const str = std.fmt.bufPrint(&buf, "{s}@{d}.{d}.{d}\n", .{
        pkg_id.name,
        pkg_id.version.major,
        pkg_id.version.minor,
        pkg_id.version.patch,
    }) catch unreachable;
    try writer.writeAll(str);

    // Find and print dependencies
    const key = packageIdToKey(std.heap.page_allocator, pkg_id) catch return;
    defer std.heap.page_allocator.free(key);

    if (closure.entries.get(key)) |entry| {
        // Find packages that this one depends on
        var iter = closure.entries.iterator();
        while (iter.next()) |e| {
            for (e.value_ptr.required_by) |req| {
                if (std.mem.eql(u8, req.name, pkg_id.name) and
                    req.version.major == pkg_id.version.major and
                    req.version.minor == pkg_id.version.minor and
                    req.version.patch == pkg_id.version.patch)
                {
                    try formatTreeNode(writer, closure, e.value_ptr.id, indent + 1, max_depth);
                }
            }
        }
        _ = entry;
    }
}

pub const FormatOptions = struct {
    show_tree: bool = false,
    max_depth: ?u32 = null,
    show_sizes: bool = false,
    show_provides: bool = false,
};

// Tests
test "packageIdToKey creates unique keys" {
    const allocator = std.testing.allocator;

    const pkg1 = PackageId{
        .name = "bash",
        .version = .{ .major = 5, .minor = 2, .patch = 0 },
        .revision = 1,
        .build_id = "abc123",
    };

    const key1 = try packageIdToKey(allocator, pkg1);
    defer allocator.free(key1);

    try std.testing.expectEqualStrings("bash-5.2.0-r1-abc123", key1);
}

test "packageIdToKey different packages have different keys" {
    const allocator = std.testing.allocator;

    const pkg1 = PackageId{
        .name = "bash",
        .version = .{ .major = 5, .minor = 2, .patch = 0 },
        .revision = 1,
        .build_id = "abc123",
    };

    const pkg2 = PackageId{
        .name = "bash",
        .version = .{ .major = 5, .minor = 2, .patch = 1 }, // different patch
        .revision = 1,
        .build_id = "abc123",
    };

    const key1 = try packageIdToKey(allocator, pkg1);
    defer allocator.free(key1);

    const key2 = try packageIdToKey(allocator, pkg2);
    defer allocator.free(key2);

    try std.testing.expect(!std.mem.eql(u8, key1, key2));
}

test "Closure.init and deinit" {
    const allocator = std.testing.allocator;

    var closure = Closure.init(allocator);
    defer closure.deinit();

    try std.testing.expectEqual(@as(usize, 0), closure.packageCount());
    try std.testing.expectEqual(@as(usize, 0), closure.roots.items.len);
    try std.testing.expectEqual(@as(u64, 0), closure.total_size);
}

test "Closure.isBasePackage" {
    const allocator = std.testing.allocator;

    var closure = Closure.init(allocator);
    defer closure.deinit();

    // Add some base packages
    try closure.base_packages.put("libc", {});
    try closure.base_packages.put("libm", {});

    try std.testing.expect(closure.isBasePackage("libc"));
    try std.testing.expect(closure.isBasePackage("libm"));
    try std.testing.expect(!closure.isBasePackage("openssl"));
}

test "getClosureStats empty closure" {
    const allocator = std.testing.allocator;

    var closure = Closure.init(allocator);
    defer closure.deinit();

    const stats = getClosureStats(&closure);
    try std.testing.expectEqual(@as(usize, 0), stats.package_count);
    try std.testing.expectEqual(@as(u32, 0), stats.max_depth);
    try std.testing.expectEqual(@as(usize, 0), stats.root_count);
}

test "getClosureStats with base packages" {
    const allocator = std.testing.allocator;

    var closure = Closure.init(allocator);
    defer closure.deinit();

    try closure.base_packages.put("libc", {});
    try closure.base_packages.put("libm", {});
    try closure.base_packages.put("libpthread", {});

    const stats = getClosureStats(&closure);
    try std.testing.expectEqual(@as(usize, 3), stats.base_excluded_count);
}

test "cloneManifest basic" {
    const allocator = std.testing.allocator;

    var original = Manifest{
        .name = "test-pkg",
        .version = .{ .major = 1, .minor = 2, .patch = 3 },
        .revision = 5,
        .description = "A test package",
        .license = "MIT",
        .homepage = "https://example.com",
        .maintainer = "test@example.com",
        .tags = &[_][]const u8{},
        .provides = &[_][]const u8{},
        .conflicts = &[_]manifest.VirtualPackage{},
        .replaces = &[_]manifest.VirtualPackage{},
    };

    var cloned = try cloneManifest(allocator, original);
    defer cloned.deinit(allocator);

    try std.testing.expectEqualStrings("test-pkg", cloned.name);
    try std.testing.expectEqual(@as(u32, 1), cloned.version.major);
    try std.testing.expectEqual(@as(u32, 2), cloned.version.minor);
    try std.testing.expectEqual(@as(u32, 3), cloned.version.patch);
    try std.testing.expectEqual(@as(u32, 5), cloned.revision);
    try std.testing.expectEqualStrings("A test package", cloned.description.?);
    try std.testing.expectEqualStrings("MIT", cloned.license.?);
}

test "cloneManifest with tags" {
    const allocator = std.testing.allocator;

    const tags = [_][]const u8{ "cli", "shell" };
    var original = Manifest{
        .name = "bash",
        .version = .{ .major = 5, .minor = 0, .patch = 0 },
        .revision = 1,
        .tags = @constCast(&tags),
        .provides = &[_][]const u8{},
        .conflicts = &[_]manifest.VirtualPackage{},
        .replaces = &[_]manifest.VirtualPackage{},
    };

    var cloned = try cloneManifest(allocator, original);
    defer cloned.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), cloned.tags.len);
    try std.testing.expectEqualStrings("cli", cloned.tags[0]);
    try std.testing.expectEqualStrings("shell", cloned.tags[1]);
}

test "cloneManifest independence" {
    const allocator = std.testing.allocator;

    const original_name = try allocator.dupe(u8, "original");
    defer allocator.free(original_name);

    var original = Manifest{
        .name = original_name,
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .revision = 1,
        .tags = &[_][]const u8{},
        .provides = &[_][]const u8{},
        .conflicts = &[_]manifest.VirtualPackage{},
        .replaces = &[_]manifest.VirtualPackage{},
    };

    var cloned = try cloneManifest(allocator, original);
    defer cloned.deinit(allocator);

    // Cloned name should be independent copy
    try std.testing.expect(original.name.ptr != cloned.name.ptr);
    try std.testing.expectEqualStrings("original", cloned.name);
}

test "FormatOptions defaults" {
    const options = FormatOptions{};
    try std.testing.expect(!options.show_tree);
    try std.testing.expect(options.max_depth == null);
    try std.testing.expect(!options.show_sizes);
    try std.testing.expect(!options.show_provides);
}

test "ClosureStats struct" {
    const stats = ClosureStats{
        .package_count = 10,
        .total_size_bytes = 1024 * 1024,
        .max_depth = 5,
        .root_count = 2,
        .base_excluded_count = 7,
    };

    try std.testing.expectEqual(@as(usize, 10), stats.package_count);
    try std.testing.expectEqual(@as(u64, 1024 * 1024), stats.total_size_bytes);
    try std.testing.expectEqual(@as(u32, 5), stats.max_depth);
    try std.testing.expectEqual(@as(usize, 2), stats.root_count);
    try std.testing.expectEqual(@as(usize, 7), stats.base_excluded_count);
}

test "ClosureEntry struct" {
    const allocator = std.testing.allocator;

    const required_by = try allocator.alloc(PackageId, 1);
    required_by[0] = PackageId{
        .name = "parent",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .revision = 1,
        .build_id = "abc",
    };

    var entry = ClosureEntry{
        .id = PackageId{
            .name = "child",
            .version = .{ .major = 2, .minor = 0, .patch = 0 },
            .revision = 1,
            .build_id = "def",
        },
        .manifest = undefined,
        .depth = 1,
        .required_by = required_by,
    };

    try std.testing.expectEqual(@as(u32, 1), entry.depth);
    try std.testing.expectEqual(@as(usize, 1), entry.required_by.len);
    try std.testing.expectEqualStrings("parent", entry.required_by[0].name);

    entry.deinit(allocator);
}
