const std = @import("std");
const types = @import("types.zig");
const zfs = @import("zfs.zig");
const manifest = @import("manifest.zig");
const format_version = @import("format_version.zig");

const Version = types.Version;
const VersionConstraint = types.VersionConstraint;
const Dependency = types.Dependency;
const PackageId = types.PackageId;
const ZfsHandle = zfs.ZfsHandle;
const FormatVersions = format_version.FormatVersions;

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

    /// Features to enable for this package
    features: []const []const u8 = &[_][]const u8{},

    /// Features to explicitly disable (overrides defaults)
    disabled_features: []const []const u8 = &[_][]const u8{},
};

/// Version preference for resolver optimization (Phase 43)
pub const Preference = struct {
    /// Package name this preference applies to
    name: []const u8,

    /// Preferred version pattern (e.g., "3.11.*")
    prefer: ?[]const u8 = null,

    /// Version pattern to avoid (e.g., "3.12.*")
    avoid: ?[]const u8 = null,

    /// Weight for preference (higher = stronger preference)
    weight: i32 = 100,

    pub fn deinit(self: *Preference, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        if (self.prefer) |p| allocator.free(p);
        if (self.avoid) |a| allocator.free(a);
    }
};

/// Version pin for exact version locking (Phase 43)
pub const Pin = struct {
    /// Package name to pin
    name: []const u8,

    /// Exact version to pin to
    version: []const u8,

    /// Optional reason for the pin
    reason: ?[]const u8 = null,

    pub fn deinit(self: *Pin, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.version);
        if (self.reason) |r| allocator.free(r);
    }
};

/// A resolved package (after dependency resolution)
pub const ResolvedPackage = struct {
    id: PackageId,
    requested: bool, // true if directly requested, false if dependency
};

/// Profile definition (profile.yaml)
pub const Profile = struct {
    /// Format version for this profile file (e.g., "1.0")
    format_version: ?[]const u8 = null,

    name: []const u8,
    description: ?[]const u8 = null,
    packages: []PackageRequest,

    /// Version preferences for resolver optimization (Phase 43)
    preferences: []Preference = &[_]Preference{},

    /// Version pins for exact version locking (Phase 43)
    pins: []Pin = &[_]Pin{},

    /// Parse profile from YAML content
    ///
    /// YAML Subset Supported:
    /// ----------------------
    /// This is a minimal line-based YAML parser optimized for Axiom profiles.
    /// It does NOT support the full YAML specification.
    ///
    /// Supported features:
    /// - Single-line key: value pairs
    /// - List items with "- " prefix for packages section
    /// - Nested package attributes (name, version, constraint)
    /// - Comments starting with #
    /// - Quoted values (quotes are stripped)
    ///
    /// NOT supported:
    /// - Multi-line strings (| or > syntax)
    /// - Deeply nested structures
    /// - Escaped quotes within values
    /// - Flow syntax ({ } or [ ])
    /// - Anchors and aliases
    ///
    /// Example of supported format:
    /// ```yaml
    /// name: my-profile
    /// description: Development environment
    /// packages:
    ///   - name: gcc
    ///     version: "13.2.0"
    ///     constraint: exact
    ///   - name: python
    ///     version: "3.11"
    ///     constraint: minimum
    /// ```
    pub fn parse(allocator: std.mem.Allocator, yaml_content: []const u8) !Profile {
        var profile = Profile{
            .name = undefined,
            .packages = &[_]PackageRequest{},
        };

        var lines = std.mem.splitScalar(u8, yaml_content, '\n');
        var packages: std.ArrayList(PackageRequest) = .empty;
        defer packages.deinit(allocator);

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
                        try packages.append(allocator, .{
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

            if (std.mem.eql(u8, key, "format_version")) {
                profile.format_version = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "name")) {
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
                try packages.append(allocator, .{
                    .name = try allocator.dupe(u8, name),
                    .constraint = constraint,
                });
            }
        }

        profile.packages = try packages.toOwnedSlice(allocator);
        return profile;
    }

    /// Write profile to YAML format
    pub fn write(self: Profile, writer: anytype) !void {
        // Always write format_version first
        try std.fmt.format(writer, "format_version: \"{s}\"\n", .{FormatVersions.profile});
        try std.fmt.format(writer, "name: {s}\n", .{self.name});
        if (self.description) |desc| {
            try std.fmt.format(writer, "description: {s}\n", .{desc});
        }

        try writer.writeAll("packages:\n");
        for (self.packages) |pkg| {
            try std.fmt.format(writer, "  - name: {s}\n", .{pkg.name});
            switch (pkg.constraint) {
                .exact => |v| {
                    try std.fmt.format(writer, "    version: \"{f}\"\n", .{v});
                    try writer.writeAll("    constraint: exact\n");
                },
                .tilde => |v| {
                    try std.fmt.format(writer, "    version: \"~{f}\"\n", .{v});
                    try writer.writeAll("    constraint: tilde\n");
                },
                .caret => |v| {
                    try std.fmt.format(writer, "    version: \"^{f}\"\n", .{v});
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
                            try std.fmt.format(writer, ">={f}", .{min});
                        } else {
                            try std.fmt.format(writer, ">{f}", .{min});
                        }
                    }
                    if (r.max) |max| {
                        if (r.min != null) {
                            try writer.writeAll(",");
                        }
                        if (r.max_inclusive) {
                            try std.fmt.format(writer, "<={f}", .{max});
                        } else {
                            try std.fmt.format(writer, "<{f}", .{max});
                        }
                    }
                    try writer.writeAll("\"\n");
                    try writer.writeAll("    constraint: range\n");
                },
            }
        }
    }

    /// Validate profile format version
    pub fn validate(self: Profile) !void {
        if (self.format_version) |fv| {
            format_version.validateVersion(.profile, fv) catch |err| {
                return switch (err) {
                    format_version.VersionError.IncompatibleMajorVersion => error.IncompatibleFormatVersion,
                    format_version.VersionError.VersionTooNew => error.FormatVersionTooNew,
                    format_version.VersionError.InvalidVersion => error.InvalidFormatVersion,
                    else => error.InvalidFormatVersion,
                };
            };
        }
    }

    /// Get the current format version string for writing profiles
    pub fn currentFormatVersion() []const u8 {
        return FormatVersions.profile;
    }

    /// Free all allocated memory
    pub fn deinit(self: *Profile, allocator: std.mem.Allocator) void {
        if (self.format_version) |fv| allocator.free(fv);
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
    /// Format version for this lock file (e.g., "1.0")
    format_version: ?[]const u8 = null,

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
        var resolved: std.ArrayList(ResolvedPackage) = .empty;
        defer resolved.deinit(allocator);

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
                        try resolved.append(allocator, .{
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

            if (std.mem.eql(u8, key, "format_version")) {
                lock.format_version = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "profile_name")) {
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
                try resolved.append(allocator, .{
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

        lock.resolved = try resolved.toOwnedSlice(allocator);
        return lock;
    }

    /// Write lock file to YAML format
    pub fn write(self: ProfileLock, writer: anytype) !void {
        // Always write format_version first
        try std.fmt.format(writer, "format_version: \"{s}\"\n", .{FormatVersions.lock});
        try std.fmt.format(writer, "profile_name: {s}\n", .{self.profile_name});
        try std.fmt.format(writer, "lock_version: {d}\n", .{self.lock_version});
        try writer.writeAll("resolved:\n");

        for (self.resolved) |pkg| {
            try std.fmt.format(writer, "  - name: {s}\n", .{pkg.id.name});
            try std.fmt.format(writer, "    version: \"{f}\"\n", .{pkg.id.version});
            try std.fmt.format(writer, "    revision: {d}\n", .{pkg.id.revision});
            try std.fmt.format(writer, "    build_id: {s}\n", .{pkg.id.build_id});
            try std.fmt.format(writer, "    requested: {}\n", .{pkg.requested});
        }
    }

    /// Validate lock file format version
    pub fn validate(self: ProfileLock) !void {
        if (self.format_version) |fv| {
            format_version.validateVersion(.lock, fv) catch |err| {
                return switch (err) {
                    format_version.VersionError.IncompatibleMajorVersion => error.IncompatibleFormatVersion,
                    format_version.VersionError.VersionTooNew => error.FormatVersionTooNew,
                    format_version.VersionError.InvalidVersion => error.InvalidFormatVersion,
                    else => error.InvalidFormatVersion,
                };
            };
        }
    }

    /// Get the current format version string for writing lock files
    pub fn currentFormatVersion() []const u8 {
        return FormatVersions.lock;
    }

    /// Free all allocated memory
    pub fn deinit(self: *ProfileLock, allocator: std.mem.Allocator) void {
        if (self.format_version) |fv| allocator.free(fv);
        allocator.free(self.profile_name);
        for (self.resolved) |pkg| {
            allocator.free(pkg.id.name);
            allocator.free(pkg.id.build_id);
        }
        allocator.free(self.resolved);
    }
};

/// Profile manager for creating and managing profiles
/// Thread-safe: Uses atomic file writes to prevent race conditions
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

    /// Atomically write content to a file using temp file + rename pattern
    /// This prevents race conditions where concurrent writes could corrupt the file
    fn atomicWriteFile(self: *ProfileManager, path: []const u8, content: []const u8) !void {
        // Generate unique temp file path in the same directory (for atomic rename)
        const dir_path = std.fs.path.dirname(path) orelse ".";
        const basename = std.fs.path.basename(path);

        // Use timestamp and random suffix for uniqueness
        const timestamp = std.time.timestamp();
        const random = std.crypto.random.int(u32);

        const temp_path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/.{s}.{d}.{d}.tmp",
            .{ dir_path, basename, timestamp, random },
        );
        defer self.allocator.free(temp_path);

        // Write to temp file
        const temp_file = try std.fs.cwd().createFile(temp_path, .{
            .exclusive = true, // Fail if file exists (extra safety)
        });
        errdefer {
            temp_file.close();
            std.fs.cwd().deleteFile(temp_path) catch {};
        }

        try temp_file.writeAll(content);
        try temp_file.sync(); // Ensure data is flushed to disk
        temp_file.close();

        // Atomic rename (POSIX guarantees atomicity for rename on same filesystem)
        try std.fs.cwd().rename(temp_path, path);
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

        // Ensure the dataset is mounted
        self.zfs_handle.mount(self.allocator, dataset_path, null) catch |err| {
            // Ignore if already mounted
            if (err != error.DatasetBusy) {
                std.debug.print("Warning: Could not mount {s}: {}\n", .{ dataset_path, err });
            }
        };

        // Get mountpoint
        const mountpoint = try self.zfs_handle.getMountpoint(self.allocator, dataset_path);
        defer self.allocator.free(mountpoint);

        // Ensure mountpoint directory exists (in case ZFS didn't create it)
        std.fs.makeDirAbsolute(mountpoint) catch |err| {
            if (err != error.PathAlreadyExists) {
                std.debug.print("Warning: Could not create mountpoint dir {s}: {}\n", .{ mountpoint, err });
            }
        };

        // Write profile.yaml atomically
        const profile_path = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ mountpoint, "profile.yaml" },
        );
        defer self.allocator.free(profile_path);

        // Build content in memory first
        var content: std.ArrayList(u8) = .empty;
        defer content.deinit(self.allocator);
        try profile.write(content.writer(self.allocator));

        // Atomically write to file
        try self.atomicWriteFile(profile_path, content.items);

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

        // Snapshot before update (use milliseconds to avoid collisions)
        const timestamp_ms = std.time.milliTimestamp();
        const snap_name = try std.fmt.allocPrint(
            self.allocator,
            "pre-update-{d}",
            .{timestamp_ms},
        );
        defer self.allocator.free(snap_name);

        try self.zfs_handle.snapshot(self.allocator, dataset_path, snap_name, false);

        // Update profile.yaml atomically
        const profile_path = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ mountpoint, "profile.yaml" },
        );
        defer self.allocator.free(profile_path);

        // Build content in memory first
        var content: std.ArrayList(u8) = .empty;
        defer content.deinit(self.allocator);
        try profile.write(content.writer(self.allocator));

        // Atomically write to file
        try self.atomicWriteFile(profile_path, content.items);

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

    /// Save a lock file for a profile atomically
    /// Thread-safe: Uses atomic write pattern (temp file + rename)
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

        // Write profile.lock.yaml atomically
        const lock_path = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ mountpoint, "profile.lock.yaml" },
        );
        defer self.allocator.free(lock_path);

        // Build content in memory first
        var content: std.ArrayList(u8) = .empty;
        defer content.deinit(self.allocator);
        try lock.write(content.writer(self.allocator));

        // Atomically write to file
        try self.atomicWriteFile(lock_path, content.items);

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

    /// Add a package to an existing profile
    pub fn addPackageToProfile(
        self: *ProfileManager,
        profile_name: []const u8,
        package_name: []const u8,
        version_constraint: ?[]const u8,
    ) !void {
        // Load existing profile
        const prof = try self.loadProfile(profile_name);
        defer {
            self.allocator.free(prof.name);
            if (prof.description) |d| self.allocator.free(d);
            for (prof.packages) |pkg| {
                self.allocator.free(pkg.name);
            }
            self.allocator.free(prof.packages);
        }

        // Check if package already exists
        for (prof.packages) |pkg| {
            if (std.mem.eql(u8, pkg.name, package_name)) {
                std.debug.print("Package '{s}' already in profile '{s}'\n", .{ package_name, profile_name });
                return;
            }
        }

        // Parse version constraint
        const constraint = if (version_constraint) |vc|
            try parseVersionConstraintString(vc)
        else
            VersionConstraint{ .any = {} };

        // Create new packages array with the additional package
        const new_packages = try self.allocator.alloc(PackageRequest, prof.packages.len + 1);
        errdefer self.allocator.free(new_packages);

        // Copy existing packages
        for (prof.packages, 0..) |pkg, i| {
            new_packages[i] = .{
                .name = try self.allocator.dupe(u8, pkg.name),
                .constraint = pkg.constraint,
            };
        }

        // Add new package
        new_packages[prof.packages.len] = .{
            .name = try self.allocator.dupe(u8, package_name),
            .constraint = constraint,
        };

        // Create updated profile
        const updated_profile = Profile{
            .name = try self.allocator.dupe(u8, prof.name),
            .description = if (prof.description) |d| try self.allocator.dupe(u8, d) else null,
            .packages = new_packages,
        };
        defer {
            self.allocator.free(updated_profile.name);
            if (updated_profile.description) |d| self.allocator.free(d);
            for (updated_profile.packages) |pkg| {
                self.allocator.free(pkg.name);
            }
            self.allocator.free(updated_profile.packages);
        }

        // Save updated profile
        try self.updateProfile(updated_profile);

        std.debug.print("✓ Added '{s}' to profile '{s}'\n", .{ package_name, profile_name });
    }

    /// Remove a package from an existing profile
    pub fn removePackageFromProfile(
        self: *ProfileManager,
        profile_name: []const u8,
        package_name: []const u8,
    ) !void {
        // Load existing profile
        const prof = try self.loadProfile(profile_name);
        defer {
            self.allocator.free(prof.name);
            if (prof.description) |d| self.allocator.free(d);
            for (prof.packages) |pkg| {
                self.allocator.free(pkg.name);
            }
            self.allocator.free(prof.packages);
        }

        // Find package index
        var found_index: ?usize = null;
        for (prof.packages, 0..) |pkg, i| {
            if (std.mem.eql(u8, pkg.name, package_name)) {
                found_index = i;
                break;
            }
        }

        if (found_index == null) {
            std.debug.print("Package '{s}' not found in profile '{s}'\n", .{ package_name, profile_name });
            return;
        }

        // Create new packages array without the removed package
        if (prof.packages.len == 1) {
            // Removing last package - create empty array
            const new_packages = try self.allocator.alloc(PackageRequest, 0);

            const updated_profile = Profile{
                .name = try self.allocator.dupe(u8, prof.name),
                .description = if (prof.description) |d| try self.allocator.dupe(u8, d) else null,
                .packages = new_packages,
            };
            defer {
                self.allocator.free(updated_profile.name);
                if (updated_profile.description) |d| self.allocator.free(d);
                self.allocator.free(updated_profile.packages);
            }

            try self.updateProfile(updated_profile);
        } else {
            var new_packages = try self.allocator.alloc(PackageRequest, prof.packages.len - 1);
            errdefer self.allocator.free(new_packages);

            var j: usize = 0;
            for (prof.packages, 0..) |pkg, i| {
                if (i != found_index.?) {
                    new_packages[j] = .{
                        .name = try self.allocator.dupe(u8, pkg.name),
                        .constraint = pkg.constraint,
                    };
                    j += 1;
                }
            }

            const updated_profile = Profile{
                .name = try self.allocator.dupe(u8, prof.name),
                .description = if (prof.description) |d| try self.allocator.dupe(u8, d) else null,
                .packages = new_packages,
            };
            defer {
                self.allocator.free(updated_profile.name);
                if (updated_profile.description) |d| self.allocator.free(d);
                for (updated_profile.packages) |pkg| {
                    self.allocator.free(pkg.name);
                }
                self.allocator.free(updated_profile.packages);
            }

            try self.updateProfile(updated_profile);
        }

        std.debug.print("✓ Removed '{s}' from profile '{s}'\n", .{ package_name, profile_name });
    }
};

/// Parse a version constraint from a user-provided string
/// Supports: "*", "1.2.3" (exact), "^1.2.3" (caret), "~1.2.3" (tilde), ">=1.0.0" (range)
fn parseVersionConstraintString(version_str: []const u8) !VersionConstraint {
    const trimmed = std.mem.trim(u8, version_str, " \t\"");

    if (trimmed.len == 0 or std.mem.eql(u8, trimmed, "*")) {
        return VersionConstraint{ .any = {} };
    }

    if (std.mem.startsWith(u8, trimmed, "^")) {
        const v = try Version.parse(trimmed[1..]);
        return VersionConstraint{ .caret = v };
    }

    if (std.mem.startsWith(u8, trimmed, "~")) {
        const v = try Version.parse(trimmed[1..]);
        return VersionConstraint{ .tilde = v };
    }

    if (std.mem.startsWith(u8, trimmed, ">=") or std.mem.startsWith(u8, trimmed, ">") or
        std.mem.startsWith(u8, trimmed, "<=") or std.mem.startsWith(u8, trimmed, "<"))
    {
        // Parse as range
        var min: ?Version = null;
        var max: ?Version = null;
        var min_inclusive = true;
        var max_inclusive = true;

        var parts = std.mem.splitScalar(u8, trimmed, ',');
        while (parts.next()) |part| {
            const p = std.mem.trim(u8, part, " \t");
            if (std.mem.startsWith(u8, p, ">=")) {
                min = try Version.parse(p[2..]);
                min_inclusive = true;
            } else if (std.mem.startsWith(u8, p, ">")) {
                min = try Version.parse(p[1..]);
                min_inclusive = false;
            } else if (std.mem.startsWith(u8, p, "<=")) {
                max = try Version.parse(p[2..]);
                max_inclusive = true;
            } else if (std.mem.startsWith(u8, p, "<")) {
                max = try Version.parse(p[1..]);
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

    // Default: exact version
    const v = try Version.parse(trimmed);
    return VersionConstraint{ .exact = v };
}

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
