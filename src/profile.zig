const std = @import("std");
const types = @import("types.zig");
const zfs = @import("zfs.zig");
const manifest = @import("manifest.zig");

const Version = types.Version;
const VersionConstraint = types.VersionConstraint;
const Dependency = types.Dependency;
const PackageId = types.PackageId;
const ZfsHandle = zfs.ZfsHandle;

/// Errors that can occur during profile operations
pub const ProfileError = error{
    ProfileExists,
    ProfileNotFound,
    InvalidProfile,
    LockFileMissing,
    WriteError,
};

/// A package request in a profile (before resolution)
pub const PackageRequest = struct {
    name: []const u8,
    constraint: VersionConstraint,
};

/// A resolved package (after dependency resolution)
pub const ResolvedPackage = struct {
    id: PackageId,
    requested: bool, // true if directly requested, false if dependency
};

/// Profile definition (profile.yaml)
pub const Profile = struct {
    name: []const u8,
    description: ?[]const u8 = null,
    packages: []PackageRequest,

    /// Parse profile from YAML content
    pub fn parse(allocator: std.mem.Allocator, yaml_content: []const u8) !Profile {
        var profile = Profile{
            .name = undefined,
            .packages = &[_]PackageRequest{},
        };

        var lines = std.mem.splitScalar(u8, yaml_content, '\n');
        var packages = std.ArrayList(PackageRequest).init(allocator);
        defer packages.deinit();

        var current_pkg: ?struct {
            name: ?[]const u8 = null,
            version: ?[]const u8 = null,
            constraint_type: ?[]const u8 = null,
        } = null;

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0) continue;
            if (std.mem.startsWith(u8, trimmed, "#")) continue;

            if (std.mem.startsWith(u8, trimmed, "- ")) {
                // Finalize previous package
                if (current_pkg) |pkg| {
                    if (pkg.name) |name| {
                        const constraint = try parseConstraint(
                            allocator,
                            pkg.version orelse "*",
                            pkg.constraint_type orelse "any",
                        );
                        try packages.append(.{
                            .name = try allocator.dupe(u8, name),
                            .constraint = constraint,
                        });
                    }
                }
                current_pkg = .{};
                continue;
            }

            var parts = std.mem.splitScalar(u8, trimmed, ':');
            const key = std.mem.trim(u8, parts.next() orelse continue, " \t");
            const value = std.mem.trim(u8, parts.rest(), " \t\"");

            if (std.mem.eql(u8, key, "name")) {
                if (current_pkg == null) {
                    profile.name = try allocator.dupe(u8, value);
                } else {
                    current_pkg.?.name = value;
                }
            } else if (std.mem.eql(u8, key, "description")) {
                profile.description = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "version")) {
                if (current_pkg) |*pkg| {
                    pkg.version = value;
                }
            } else if (std.mem.eql(u8, key, "constraint")) {
                if (current_pkg) |*pkg| {
                    pkg.constraint_type = value;
                }
            }
        }

        // Finalize last package
        if (current_pkg) |pkg| {
            if (pkg.name) |name| {
                const constraint = try parseConstraint(
                    allocator,
                    pkg.version orelse "*",
                    pkg.constraint_type orelse "any",
                );
                try packages.append(.{
                    .name = try allocator.dupe(u8, name),
                    .constraint = constraint,
                });
            }
        }

        profile.packages = try packages.toOwnedSlice();
        return profile;
    }

    /// Write profile to YAML format
    pub fn write(self: Profile, writer: anytype) !void {
        try writer.print("name: {s}\n", .{self.name});
        if (self.description) |desc| {
            try writer.print("description: {s}\n", .{desc});
        }

        try writer.writeAll("packages:\n");
        for (self.packages) |pkg| {
            try writer.print("  - name: {s}\n", .{pkg.name});
            switch (pkg.constraint) {
                .exact => |v| {
                    try writer.print("    version: \"{}\"\n", .{v});
                    try writer.writeAll("    constraint: exact\n");
                },
                .tilde => |v| {
                    try writer.print("    version: \"~{}\"\n", .{v});
                    try writer.writeAll("    constraint: tilde\n");
                },
                .caret => |v| {
                    try writer.print("    version: \"^{}\"\n", .{v});
                    try writer.writeAll("    constraint: caret\n");
                },
                .any => {
                    try writer.writeAll("    version: \"*\"\n");
                    try writer.writeAll("    constraint: any\n");
                },
                .range => |r| {
                    try writer.writeAll("    version: \"");
                    if (r.min) |min| {
                        if (r.min_inclusive) {
                            try writer.print(">={}", .{min});
                        } else {
                            try writer.print(">{}", .{min});
                        }
                    }
                    if (r.max) |max| {
                        if (r.min != null) {
                            try writer.writeAll(",");
                        }
                        if (r.max_inclusive) {
                            try writer.print("<={}", .{max});
                        } else {
                            try writer.print("<{}", .{max});
                        }
                    }
                    try writer.writeAll("\"\n");
                    try writer.writeAll("    constraint: range\n");
                },
            }
        }
    }

    /// Free all allocated memory
    pub fn deinit(self: *Profile, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        if (self.description) |d| allocator.free(d);
        for (self.packages) |pkg| {
            allocator.free(pkg.name);
        }
        allocator.free(self.packages);
    }
};

/// Profile lock file (profile.lock.yaml) - resolved dependencies
pub const ProfileLock = struct {
    profile_name: []const u8,
    lock_version: u32 = 1,
    resolved: []ResolvedPackage,

    /// Parse lock file from YAML content
    pub fn parse(allocator: std.mem.Allocator, yaml_content: []const u8) !ProfileLock {
        var lock = ProfileLock{
            .profile_name = undefined,
            .lock_version = 1,
            .resolved = &[_]ResolvedPackage{},
        };

        var lines = std.mem.splitScalar(u8, yaml_content, '\n');
        var resolved = std.ArrayList(ResolvedPackage).init(allocator);
        defer resolved.deinit();

        var current_pkg: ?struct {
            name: ?[]const u8 = null,
            version: ?[]const u8 = null,
            revision: ?u32 = null,
            build_id: ?[]const u8 = null,
            requested: bool = false,
        } = null;

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0) continue;
            if (std.mem.startsWith(u8, trimmed, "#")) continue;

            if (std.mem.startsWith(u8, trimmed, "- ")) {
                // Finalize previous package
                if (current_pkg) |pkg| {
                    if (pkg.name != null and pkg.version != null and 
                        pkg.revision != null and pkg.build_id != null) {
                        const version = try Version.parse(pkg.version.?);
                        try resolved.append(.{
                            .id = .{
                                .name = try allocator.dupe(u8, pkg.name.?),
                                .version = version,
                                .revision = pkg.revision.?,
                                .build_id = try allocator.dupe(u8, pkg.build_id.?),
                            },
                            .requested = pkg.requested,
                        });
                    }
                }
                current_pkg = .{};
                continue;
            }

            var parts = std.mem.splitScalar(u8, trimmed, ':');
            const key = std.mem.trim(u8, parts.next() orelse continue, " \t");
            const value = std.mem.trim(u8, parts.rest(), " \t\"");

            if (std.mem.eql(u8, key, "profile_name")) {
                lock.profile_name = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "lock_version")) {
                lock.lock_version = try std.fmt.parseInt(u32, value, 10);
            } else if (std.mem.eql(u8, key, "name")) {
                if (current_pkg) |*pkg| {
                    pkg.name = value;
                }
            } else if (std.mem.eql(u8, key, "version")) {
                if (current_pkg) |*pkg| {
                    pkg.version = value;
                }
            } else if (std.mem.eql(u8, key, "revision")) {
                if (current_pkg) |*pkg| {
                    pkg.revision = try std.fmt.parseInt(u32, value, 10);
                }
            } else if (std.mem.eql(u8, key, "build_id")) {
                if (current_pkg) |*pkg| {
                    pkg.build_id = value;
                }
            } else if (std.mem.eql(u8, key, "requested")) {
                if (current_pkg) |*pkg| {
                    pkg.requested = std.mem.eql(u8, value, "true");
                }
            }
        }

        // Finalize last package
        if (current_pkg) |pkg| {
            if (pkg.name != null and pkg.version != null and 
                pkg.revision != null and pkg.build_id != null) {
                const version = try Version.parse(pkg.version.?);
                try resolved.append(.{
                    .id = .{
                        .name = try allocator.dupe(u8, pkg.name.?),
                        .version = version,
                        .revision = pkg.revision.?,
                        .build_id = try allocator.dupe(u8, pkg.build_id.?),
                    },
                    .requested = pkg.requested,
                });
            }
        }

        lock.resolved = try resolved.toOwnedSlice();
        return lock;
    }

    /// Write lock file to YAML format
    pub fn write(self: ProfileLock, writer: anytype) !void {
        try writer.print("profile_name: {s}\n", .{self.profile_name});
        try writer.print("lock_version: {d}\n", .{self.lock_version});
        try writer.writeAll("resolved:\n");

        for (self.resolved) |pkg| {
            try writer.print("  - name: {s}\n", .{pkg.id.name});
            try writer.print("    version: \"{}\"\n", .{pkg.id.version});
            try writer.print("    revision: {d}\n", .{pkg.id.revision});
            try writer.print("    build_id: {s}\n", .{pkg.id.build_id});
            try writer.print("    requested: {}\n", .{pkg.requested});
        }
    }

    /// Free all allocated memory
    pub fn deinit(self: *ProfileLock, allocator: std.mem.Allocator) void {
        allocator.free(self.profile_name);
        for (self.resolved) |pkg| {
            allocator.free(pkg.id.name);
            allocator.free(pkg.id.build_id);
        }
        allocator.free(self.resolved);
    }
};

/// Profile manager for creating and managing profiles
pub const ProfileManager = struct {
    allocator: std.mem.Allocator,
    zfs_handle: *ZfsHandle,
    profile_root: []const u8 = "zroot/axiom/profiles",

    /// Initialize profile manager
    pub fn init(allocator: std.mem.Allocator, zfs_handle: *ZfsHandle) ProfileManager {
        return ProfileManager{
            .allocator = allocator,
            .zfs_handle = zfs_handle,
        };
    }

    /// Create a new profile
    pub fn createProfile(
        self: *ProfileManager,
        profile: Profile,
    ) !void {
        const dataset_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.profile_root, profile.name },
        );
        defer self.allocator.free(dataset_path);

        std.debug.print("Creating profile: {s}\n", .{dataset_path});

        // Check if profile already exists
        const exists = try self.zfs_handle.datasetExists(
            self.allocator,
            dataset_path,
            .filesystem,
        );

        if (exists) {
            return ProfileError.ProfileExists;
        }

        // Create profile dataset
        try self.zfs_handle.createDataset(self.allocator, dataset_path, .{
            .compression = "lz4",
            .atime = false,
        });

        // Get mountpoint
        const mountpoint = try self.zfs_handle.getMountpoint(self.allocator, dataset_path);
        defer self.allocator.free(mountpoint);

        // Write profile.yaml
        const profile_path = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ mountpoint, "profile.yaml" },
        );
        defer self.allocator.free(profile_path);

        const file = try std.fs.cwd().createFile(profile_path, .{});
        defer file.close();

        try profile.write(file.writer());

        std.debug.print("  ✓ Profile created at {s}\n", .{mountpoint});
    }

    /// Update an existing profile
    pub fn updateProfile(
        self: *ProfileManager,
        profile: Profile,
    ) !void {
        const dataset_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.profile_root, profile.name },
        );
        defer self.allocator.free(dataset_path);

        // Check if profile exists
        const exists = try self.zfs_handle.datasetExists(
            self.allocator,
            dataset_path,
            .filesystem,
        );

        if (!exists) {
            return ProfileError.ProfileNotFound;
        }

        // Get mountpoint
        const mountpoint = try self.zfs_handle.getMountpoint(self.allocator, dataset_path);
        defer self.allocator.free(mountpoint);

        // Snapshot before update
        const timestamp = std.time.timestamp();
        const snap_name = try std.fmt.allocPrint(
            self.allocator,
            "pre-update-{d}",
            .{timestamp},
        );
        defer self.allocator.free(snap_name);

        try self.zfs_handle.snapshot(self.allocator, dataset_path, snap_name, false);

        // Update profile.yaml
        const profile_path = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ mountpoint, "profile.yaml" },
        );
        defer self.allocator.free(profile_path);

        const file = try std.fs.cwd().createFile(profile_path, .{});
        defer file.close();

        try profile.write(file.writer());

        std.debug.print("Profile '{s}' updated (snapshot: {s})\n", .{ profile.name, snap_name });
    }

    /// Load a profile from disk
    pub fn loadProfile(
        self: *ProfileManager,
        name: []const u8,
    ) !Profile {
        const dataset_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.profile_root, name },
        );
        defer self.allocator.free(dataset_path);

        // Check if profile exists
        const exists = try self.zfs_handle.datasetExists(
            self.allocator,
            dataset_path,
            .filesystem,
        );

        if (!exists) {
            return ProfileError.ProfileNotFound;
        }

        // Get mountpoint
        const mountpoint = try self.zfs_handle.getMountpoint(self.allocator, dataset_path);
        defer self.allocator.free(mountpoint);

        // Read profile.yaml
        const profile_path = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ mountpoint, "profile.yaml" },
        );
        defer self.allocator.free(profile_path);

        const content = try std.fs.cwd().readFileAlloc(
            self.allocator,
            profile_path,
            1024 * 1024,
        );
        defer self.allocator.free(content);

        return Profile.parse(self.allocator, content);
    }

    /// Save a lock file for a profile
    pub fn saveLock(
        self: *ProfileManager,
        profile_name: []const u8,
        lock: ProfileLock,
    ) !void {
        const dataset_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.profile_root, profile_name },
        );
        defer self.allocator.free(dataset_path);

        // Get mountpoint
        const mountpoint = try self.zfs_handle.getMountpoint(self.allocator, dataset_path);
        defer self.allocator.free(mountpoint);

        // Write profile.lock.yaml
        const lock_path = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ mountpoint, "profile.lock.yaml" },
        );
        defer self.allocator.free(lock_path);

        const file = try std.fs.cwd().createFile(lock_path, .{});
        defer file.close();

        try lock.write(file.writer());

        std.debug.print("Lock file saved: {s}\n", .{lock_path});
    }

    /// Load a lock file for a profile
    pub fn loadLock(
        self: *ProfileManager,
        profile_name: []const u8,
    ) !ProfileLock {
        const dataset_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.profile_root, profile_name },
        );
        defer self.allocator.free(dataset_path);

        // Get mountpoint
        const mountpoint = try self.zfs_handle.getMountpoint(self.allocator, dataset_path);
        defer self.allocator.free(mountpoint);

        // Read profile.lock.yaml
        const lock_path = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ mountpoint, "profile.lock.yaml" },
        );
        defer self.allocator.free(lock_path);

        const content = try std.fs.cwd().readFileAlloc(
            self.allocator,
            lock_path,
            1024 * 1024,
        );
        defer self.allocator.free(content);

        return ProfileLock.parse(self.allocator, content);
    }

    /// Delete a profile
    pub fn deleteProfile(
        self: *ProfileManager,
        name: []const u8,
    ) !void {
        const dataset_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.profile_root, name },
        );
        defer self.allocator.free(dataset_path);

        std.debug.print("Deleting profile: {s}\n", .{dataset_path});

        try self.zfs_handle.destroyDataset(self.allocator, dataset_path, true);

        std.debug.print("  ✓ Profile deleted\n", .{});
    }
};

/// Parse version constraint from string and type
fn parseConstraint(
    allocator: std.mem.Allocator,
    version_str: []const u8,
    constraint_type: []const u8,
) !VersionConstraint {
    _ = allocator;

    if (std.mem.eql(u8, constraint_type, "any")) {
        return VersionConstraint{ .any = {} };
    } else if (std.mem.eql(u8, constraint_type, "exact")) {
        return VersionConstraint{ .exact = try Version.parse(version_str) };
    } else if (std.mem.eql(u8, constraint_type, "tilde")) {
        const v = try Version.parse(std.mem.trim(u8, version_str, "~"));
        return VersionConstraint{ .tilde = v };
    } else if (std.mem.eql(u8, constraint_type, "caret")) {
        const v = try Version.parse(std.mem.trim(u8, version_str, "^"));
        return VersionConstraint{ .caret = v };
    } else if (std.mem.eql(u8, constraint_type, "range")) {
        var min: ?Version = null;
        var max: ?Version = null;
        var min_inclusive = true;
        var max_inclusive = true;

        var parts = std.mem.splitScalar(u8, version_str, ',');
        while (parts.next()) |part| {
            const trimmed = std.mem.trim(u8, part, " \t");
            if (std.mem.startsWith(u8, trimmed, ">=")) {
                min = try Version.parse(trimmed[2..]);
                min_inclusive = true;
            } else if (std.mem.startsWith(u8, trimmed, ">")) {
                min = try Version.parse(trimmed[1..]);
                min_inclusive = false;
            } else if (std.mem.startsWith(u8, trimmed, "<=")) {
                max = try Version.parse(trimmed[2..]);
                max_inclusive = true;
            } else if (std.mem.startsWith(u8, trimmed, "<")) {
                max = try Version.parse(trimmed[1..]);
                max_inclusive = false;
            }
        }

        return VersionConstraint{
            .range = .{
                .min = min,
                .max = max,
                .min_inclusive = min_inclusive,
                .max_inclusive = max_inclusive,
            },
        };
    }

    return VersionConstraint{ .any = {} };
}
