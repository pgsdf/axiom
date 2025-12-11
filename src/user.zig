const std = @import("std");
const zfs = @import("zfs.zig");
const types = @import("types.zig");
const profile = @import("profile.zig");
const realization = @import("realization.zig");
const realization_spec = @import("realization_spec.zig");
const store = @import("store.zig");
const conflict = @import("conflict.zig");

// POSIX getuid/getgid/getpwuid - works on FreeBSD, Linux, and other POSIX systems
const c = @cImport({
    @cInclude("unistd.h");
    @cInclude("pwd.h");
    @cInclude("sys/types.h");
});

const ZfsHandle = zfs.ZfsHandle;
const Profile = profile.Profile;
const ProfileLock = profile.ProfileLock;
const ProfileManager = profile.ProfileManager;
const RealizationEngine = realization.RealizationEngine;
const PackageStore = store.PackageStore;
const PackageId = types.PackageId;
const ConflictPolicy = conflict.ConflictPolicy;
const RealizationSpec = realization_spec.RealizationSpec;
const MergeStrategy = realization_spec.MergeStrategy;

/// Access levels for user operations
pub const AccessLevel = enum {
    /// Full access (root/admin)
    root,
    /// Own profiles/environments only
    user,
    /// Group-shared profiles
    group,
    /// Read-only access (view only)
    readonly,
};

/// User context containing identity and permissions
pub const UserContext = struct {
    uid: u32,
    gid: u32,
    username: []const u8,
    groups: []const u32,
    home_dir: []const u8,
    access_level: AccessLevel,
    allocator: std.mem.Allocator,

    /// Initialize user context from current process
    pub fn init(allocator: std.mem.Allocator) !UserContext {
        // Get current user ID (using C library for cross-platform support)
        const uid = c.getuid();
        const gid = c.getgid();

        // Determine access level based on UID
        const access_level: AccessLevel = if (uid == 0) .root else .user;

        // Get username - prefer passwd database over environment for security
        // Environment variables can be spoofed, but getpwuid uses system auth
        const username = blk: {
            break :blk getUsernameFromSystem(allocator, uid) catch
                std.process.getEnvVarOwned(allocator, "USER") catch
                try allocator.dupe(u8, "unknown");
        };

        // Get home directory - prefer passwd database over environment for consistency
        const home_dir = blk: {
            const home = getHomeDirFromSystem(allocator, uid) catch
                std.process.getEnvVarOwned(allocator, "HOME") catch
                try std.fmt.allocPrint(allocator, "/home/{s}", .{username});
            break :blk home;
        };

        return UserContext{
            .uid = uid,
            .gid = gid,
            .username = username,
            .groups = &[_]u32{},
            .home_dir = home_dir,
            .access_level = access_level,
            .allocator = allocator,
        };
    }

    /// Get username from system password database (more secure than $USER)
    fn getUsernameFromSystem(allocator: std.mem.Allocator, uid: u32) ![]const u8 {
        const pw = c.getpwuid(uid);
        if (pw == null) {
            return error.UserNotFound;
        }
        const name_ptr = pw.*.pw_name;
        if (name_ptr == null) {
            return error.UserNotFound;
        }
        const name_len = std.mem.len(name_ptr);
        return try allocator.dupe(u8, name_ptr[0..name_len]);
    }

    /// Get home directory from system password database
    fn getHomeDirFromSystem(allocator: std.mem.Allocator, uid: u32) ![]const u8 {
        const pw = c.getpwuid(uid);
        if (pw == null) {
            return error.UserNotFound;
        }
        const dir_ptr = pw.*.pw_dir;
        if (dir_ptr == null) {
            return error.UserNotFound;
        }
        const dir_len = std.mem.len(dir_ptr);
        return try allocator.dupe(u8, dir_ptr[0..dir_len]);
    }

    /// Initialize user context with specific values (for testing or impersonation)
    pub fn initWith(
        allocator: std.mem.Allocator,
        uid: u32,
        gid: u32,
        username: []const u8,
        home_dir: []const u8,
    ) !UserContext {
        return UserContext{
            .uid = uid,
            .gid = gid,
            .username = try allocator.dupe(u8, username),
            .groups = &[_]u32{},
            .home_dir = try allocator.dupe(u8, home_dir),
            .access_level = if (uid == 0) .root else .user,
            .allocator = allocator,
        };
    }

    /// Check if user can modify a profile
    pub fn canModifyProfile(self: UserContext, profile_owner: []const u8) bool {
        return switch (self.access_level) {
            .root => true,
            .user => std.mem.eql(u8, self.username, profile_owner),
            .group => false, // TODO: Check group membership
            .readonly => false,
        };
    }

    /// Check if user can create environments
    pub fn canCreateEnvironment(self: UserContext) bool {
        return switch (self.access_level) {
            .root, .user => true,
            .group, .readonly => false,
        };
    }

    /// Check if user can perform system-wide operations
    pub fn canPerformSystemOps(self: UserContext) bool {
        return self.access_level == .root;
    }

    /// Check if user is root
    pub fn isRoot(self: UserContext) bool {
        return self.uid == 0;
    }

    /// Get user's Axiom data directory
    pub fn getAxiomDir(self: UserContext) ![]const u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "{s}/.axiom",
            .{self.home_dir},
        );
    }

    /// Get user's profile directory
    pub fn getProfileDir(self: UserContext) ![]const u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "{s}/.axiom/profiles",
            .{self.home_dir},
        );
    }

    /// Get user's environment directory
    pub fn getEnvDir(self: UserContext) ![]const u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "{s}/.axiom/env",
            .{self.home_dir},
        );
    }

    /// Free allocated memory
    pub fn deinit(self: *UserContext) void {
        self.allocator.free(self.username);
        self.allocator.free(self.home_dir);
    }
};

/// Errors for user operations
pub const UserError = error{
    PermissionDenied,
    UserNotFound,
    ProfileExists,
    ProfileNotFound,
    EnvironmentExists,
    EnvironmentNotFound,
    DatasetError,
    InitializationError,
};

/// User-scoped profile manager
pub const UserProfileManager = struct {
    allocator: std.mem.Allocator,
    zfs_handle: *ZfsHandle,
    user_ctx: *UserContext,
    user_dataset_root: []const u8,

    /// Initialize user profile manager
    pub fn init(
        allocator: std.mem.Allocator,
        zfs_handle: *ZfsHandle,
        user_ctx: *UserContext,
    ) UserProfileManager {
        // User datasets are stored under zroot/axiom/users/{username}
        return UserProfileManager{
            .allocator = allocator,
            .zfs_handle = zfs_handle,
            .user_ctx = user_ctx,
            .user_dataset_root = "zroot/axiom/users",
        };
    }

    /// Get user's profile dataset path
    fn getUserProfileDataset(self: *UserProfileManager, profile_name: []const u8) ![]const u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}/profiles/{s}",
            .{ self.user_dataset_root, self.user_ctx.username, profile_name },
        );
    }

    /// Get user's profiles root dataset
    fn getUserProfilesRoot(self: *UserProfileManager) ![]const u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}/profiles",
            .{ self.user_dataset_root, self.user_ctx.username },
        );
    }

    /// Ensure user's dataset structure exists
    pub fn ensureUserDatasets(self: *UserProfileManager) !void {
        // Create user root dataset if needed
        const user_root = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.user_dataset_root, self.user_ctx.username },
        );
        defer self.allocator.free(user_root);

        const user_exists = try self.zfs_handle.datasetExists(
            self.allocator,
            user_root,
            .filesystem,
        );

        if (!user_exists) {
            std.debug.print("Creating user dataset structure for '{s}'...\n", .{self.user_ctx.username});
            try self.zfs_handle.createDataset(self.allocator, user_root, .{
                .compression = "lz4",
                .atime = false,
            });
        }

        // Create profiles dataset
        const profiles_root = try self.getUserProfilesRoot();
        defer self.allocator.free(profiles_root);

        const profiles_exists = try self.zfs_handle.datasetExists(
            self.allocator,
            profiles_root,
            .filesystem,
        );

        if (!profiles_exists) {
            try self.zfs_handle.createDataset(self.allocator, profiles_root, .{
                .compression = "lz4",
                .atime = false,
            });
        }

        // Create env dataset
        const env_root = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}/env",
            .{ self.user_dataset_root, self.user_ctx.username },
        );
        defer self.allocator.free(env_root);

        const env_exists = try self.zfs_handle.datasetExists(
            self.allocator,
            env_root,
            .filesystem,
        );

        if (!env_exists) {
            try self.zfs_handle.createDataset(self.allocator, env_root, .{
                .compression = "lz4",
                .atime = false,
            });
        }

        std.debug.print("  User datasets ready\n", .{});
    }

    /// Create a new user profile
    pub fn createProfile(self: *UserProfileManager, prof: Profile) !void {
        // Ensure user datasets exist
        try self.ensureUserDatasets();

        const dataset_path = try self.getUserProfileDataset(prof.name);
        defer self.allocator.free(dataset_path);

        std.debug.print("Creating user profile: {s}\n", .{prof.name});

        // Check if profile already exists
        const exists = try self.zfs_handle.datasetExists(
            self.allocator,
            dataset_path,
            .filesystem,
        );

        if (exists) {
            return UserError.ProfileExists;
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

        try prof.write(file.writer());

        std.debug.print("  Profile created at {s}\n", .{mountpoint});
    }

    /// Load a user profile
    pub fn loadProfile(self: *UserProfileManager, name: []const u8) !Profile {
        const dataset_path = try self.getUserProfileDataset(name);
        defer self.allocator.free(dataset_path);

        const exists = try self.zfs_handle.datasetExists(
            self.allocator,
            dataset_path,
            .filesystem,
        );

        if (!exists) {
            return UserError.ProfileNotFound;
        }

        const mountpoint = try self.zfs_handle.getMountpoint(self.allocator, dataset_path);
        defer self.allocator.free(mountpoint);

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

    /// Update an existing user profile
    pub fn updateProfile(self: *UserProfileManager, prof: Profile) !void {
        const dataset_path = try self.getUserProfileDataset(prof.name);
        defer self.allocator.free(dataset_path);

        const exists = try self.zfs_handle.datasetExists(
            self.allocator,
            dataset_path,
            .filesystem,
        );

        if (!exists) {
            return UserError.ProfileNotFound;
        }

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

        // Write updated profile
        const profile_path = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ mountpoint, "profile.yaml" },
        );
        defer self.allocator.free(profile_path);

        const file = try std.fs.cwd().createFile(profile_path, .{});
        defer file.close();

        try prof.write(file.writer());

        std.debug.print("Profile '{s}' updated (snapshot: {s})\n", .{ prof.name, snap_name });
    }

    /// Delete a user profile
    pub fn deleteProfile(self: *UserProfileManager, name: []const u8) !void {
        const dataset_path = try self.getUserProfileDataset(name);
        defer self.allocator.free(dataset_path);

        std.debug.print("Deleting user profile: {s}\n", .{name});

        try self.zfs_handle.destroyDataset(self.allocator, dataset_path, true);

        std.debug.print("  Profile deleted\n", .{});
    }

    /// Save lock file for a profile
    pub fn saveLock(self: *UserProfileManager, profile_name: []const u8, lock: ProfileLock) !void {
        const dataset_path = try self.getUserProfileDataset(profile_name);
        defer self.allocator.free(dataset_path);

        const mountpoint = try self.zfs_handle.getMountpoint(self.allocator, dataset_path);
        defer self.allocator.free(mountpoint);

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

    /// Load lock file for a profile
    pub fn loadLock(self: *UserProfileManager, profile_name: []const u8) !ProfileLock {
        const dataset_path = try self.getUserProfileDataset(profile_name);
        defer self.allocator.free(dataset_path);

        const mountpoint = try self.zfs_handle.getMountpoint(self.allocator, dataset_path);
        defer self.allocator.free(mountpoint);

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

    /// List all user profiles
    pub fn listProfiles(self: *UserProfileManager) ![][]const u8 {
        const profiles_root = try self.getUserProfilesRoot();
        defer self.allocator.free(profiles_root);

        const exists = try self.zfs_handle.datasetExists(
            self.allocator,
            profiles_root,
            .filesystem,
        );

        if (!exists) {
            return &[_][]const u8{};
        }

        // List child datasets
        return self.zfs_handle.listChildDatasets(self.allocator, profiles_root);
    }
};

/// User-scoped realization engine
pub const UserRealizationEngine = struct {
    allocator: std.mem.Allocator,
    zfs_handle: *ZfsHandle,
    store: *PackageStore,
    user_ctx: *UserContext,
    user_dataset_root: []const u8,
    conflict_policy: ConflictPolicy = .error_on_conflict,

    /// Initialize user realization engine
    pub fn init(
        allocator: std.mem.Allocator,
        zfs_handle: *ZfsHandle,
        pkg_store: *PackageStore,
        user_ctx: *UserContext,
    ) UserRealizationEngine {
        return UserRealizationEngine{
            .allocator = allocator,
            .zfs_handle = zfs_handle,
            .store = pkg_store,
            .user_ctx = user_ctx,
            .user_dataset_root = "zroot/axiom/users",
        };
    }

    /// Set conflict resolution policy
    pub fn setConflictPolicy(self: *UserRealizationEngine, policy: ConflictPolicy) void {
        self.conflict_policy = policy;
    }

    /// Get user's environment dataset root
    fn getUserEnvRoot(self: *UserRealizationEngine) ![]const u8 {
        return std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}/env",
            .{ self.user_dataset_root, self.user_ctx.username },
        );
    }

    /// Create an environment from a lock file
    pub fn realize(
        self: *UserRealizationEngine,
        env_name: []const u8,
        lock: ProfileLock,
    ) !realization.Environment {
        std.debug.print("Realizing user environment: {s}\n", .{env_name});
        std.debug.print("  User: {s}\n", .{self.user_ctx.username});
        std.debug.print("  Profile: {s}\n", .{lock.profile_name});
        std.debug.print("  Packages: {d}\n", .{lock.resolved.len});

        // Get user's env root
        const env_root = try self.getUserEnvRoot();
        defer self.allocator.free(env_root);

        // Create environment dataset path
        const env_dataset = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ env_root, env_name },
        );
        defer self.allocator.free(env_dataset);

        // Check if environment already exists
        const exists = try self.zfs_handle.datasetExists(
            self.allocator,
            env_dataset,
            .filesystem,
        );

        if (exists) {
            return realization.RealizationError.EnvironmentExists;
        }

        std.debug.print("\nCreating environment dataset...\n", .{});

        // Create environment dataset
        try self.zfs_handle.createDataset(self.allocator, env_dataset, .{
            .compression = "lz4",
            .atime = false,
        });

        // Get environment mountpoint
        const env_mountpoint = try self.zfs_handle.getMountpoint(
            self.allocator,
            env_dataset,
        );
        defer self.allocator.free(env_mountpoint);

        std.debug.print("  Environment root: {s}\n", .{env_mountpoint});

        // Create directory structure
        const bin_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ env_mountpoint, "bin" });
        defer self.allocator.free(bin_dir);
        try std.fs.cwd().makePath(bin_dir);

        const lib_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ env_mountpoint, "lib" });
        defer self.allocator.free(lib_dir);
        try std.fs.cwd().makePath(lib_dir);

        const share_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ env_mountpoint, "share" });
        defer self.allocator.free(share_dir);
        try std.fs.cwd().makePath(share_dir);

        // Clone and merge all packages
        std.debug.print("\nCloning packages...\n", .{});

        var package_ids = std.ArrayList(PackageId).init(self.allocator);
        defer package_ids.deinit();

        for (lock.resolved, 0..) |pkg, i| {
            std.debug.print("  [{d}/{d}] {s} {}\n", .{
                i + 1,
                lock.resolved.len,
                pkg.id.name,
                pkg.id.version,
            });

            // Get package dataset path from shared store
            const pkg_dataset = try self.store.paths.packageDataset(self.allocator, pkg.id);
            defer self.allocator.free(pkg_dataset);

            // Verify package exists in shared store
            const pkg_exists = try self.zfs_handle.datasetExists(
                self.allocator,
                pkg_dataset,
                .filesystem,
            );

            if (!pkg_exists) {
                std.debug.print("    Package not found in store\n", .{});
                return realization.RealizationError.PackageNotFound;
            }

            // Clone package to environment
            try self.clonePackage(env_mountpoint, pkg_dataset, pkg.id);

            try package_ids.append(.{
                .name = try self.allocator.dupe(u8, pkg.id.name),
                .version = pkg.id.version,
                .revision = pkg.id.revision,
                .build_id = try self.allocator.dupe(u8, pkg.id.build_id),
            });
        }

        // Create activation script
        try self.createActivationScript(env_mountpoint, env_name);

        // Snapshot the environment
        std.debug.print("\nCreating snapshot...\n", .{});
        try self.zfs_handle.snapshot(self.allocator, env_dataset, "initial", false);

        std.debug.print("\n Environment '{s}' realized successfully\n", .{env_name});
        std.debug.print("  Location: {s}\n", .{env_mountpoint});

        return realization.Environment{
            .name = try self.allocator.dupe(u8, env_name),
            .profile_name = try self.allocator.dupe(u8, lock.profile_name),
            .dataset_path = try self.allocator.dupe(u8, env_dataset),
            .packages = try package_ids.toOwnedSlice(),
            .active = false,
        };
    }

    /// Clone a package into the environment
    fn clonePackage(
        self: *UserRealizationEngine,
        env_mountpoint: []const u8,
        pkg_dataset: []const u8,
        pkg_id: PackageId,
    ) !void {
        _ = pkg_id;

        // Get package mountpoint
        const pkg_mountpoint = try self.zfs_handle.getMountpoint(
            self.allocator,
            pkg_dataset,
        );
        defer self.allocator.free(pkg_mountpoint);

        // Package files are in root/ subdirectory
        const pkg_root = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ pkg_mountpoint, "root" },
        );
        defer self.allocator.free(pkg_root);

        // Copy files from package to environment
        const cmd = try std.fmt.allocPrint(
            self.allocator,
            "cp -R -n {s}/. {s}/",
            .{ pkg_root, env_mountpoint },
        );
        defer self.allocator.free(cmd);

        var child = std.process.Child.init(&[_][]const u8{ "sh", "-c", cmd }, self.allocator);
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Pipe;

        try child.spawn();
        const stderr = try child.stderr.?.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(stderr);

        const term = try child.wait();
        if (term.Exited != 0 and stderr.len > 0) {
            std.debug.print("    Warning: {s}\n", .{stderr});
        }
    }

    /// Realize environment with custom specification
    pub fn realizeWithSpec(
        self: *UserRealizationEngine,
        env_name: []const u8,
        lock: ProfileLock,
        spec: *const RealizationSpec,
    ) !realization.Environment {
        std.debug.print("Realizing user environment with spec: {s}\n", .{env_name});
        std.debug.print("  User: {s}\n", .{self.user_ctx.username});
        std.debug.print("  Profile: {s}\n", .{lock.profile_name});
        std.debug.print("  Packages: {d}\n", .{lock.resolved.len});
        std.debug.print("  Merge strategy: {s}\n", .{spec.default_strategy.toString()});

        // Get user's env root
        const env_root = try self.getUserEnvRoot();
        defer self.allocator.free(env_root);

        // Create environment dataset path
        const env_dataset = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ env_root, env_name },
        );
        defer self.allocator.free(env_dataset);

        // Check if environment already exists
        const exists = try self.zfs_handle.datasetExists(
            self.allocator,
            env_dataset,
            .filesystem,
        );

        if (exists) {
            return realization.RealizationError.EnvironmentExists;
        }

        std.debug.print("\nCreating environment dataset...\n", .{});

        // Create environment dataset
        try self.zfs_handle.createDataset(self.allocator, env_dataset, .{
            .compression = "lz4",
            .atime = false,
        });

        // Get environment mountpoint
        const env_mountpoint = try self.zfs_handle.getMountpoint(
            self.allocator,
            env_dataset,
        );
        defer self.allocator.free(env_mountpoint);

        std.debug.print("  Environment root: {s}\n", .{env_mountpoint});

        // Create directory structure
        const bin_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ env_mountpoint, "bin" });
        defer self.allocator.free(bin_dir);
        try std.fs.cwd().makePath(bin_dir);

        const lib_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ env_mountpoint, "lib" });
        defer self.allocator.free(lib_dir);
        try std.fs.cwd().makePath(lib_dir);

        const share_dir = try std.fs.path.join(self.allocator, &[_][]const u8{ env_mountpoint, "share" });
        defer self.allocator.free(share_dir);
        try std.fs.cwd().makePath(share_dir);

        // Clone and merge all packages with spec
        std.debug.print("\nCloning packages with spec...\n", .{});

        var package_ids = std.ArrayList(PackageId).init(self.allocator);
        defer package_ids.deinit();

        for (lock.resolved, 0..) |pkg, i| {
            std.debug.print("  [{d}/{d}] {s} {} ({s})\n", .{
                i + 1,
                lock.resolved.len,
                pkg.id.name,
                pkg.id.version,
                spec.default_strategy.toString(),
            });

            // Get package dataset path from shared store
            const pkg_dataset = try self.store.paths.packageDataset(self.allocator, pkg.id);
            defer self.allocator.free(pkg_dataset);

            // Verify package exists in shared store
            const pkg_exists = try self.zfs_handle.datasetExists(
                self.allocator,
                pkg_dataset,
                .filesystem,
            );

            if (!pkg_exists) {
                std.debug.print("    Package not found in store\n", .{});
                return realization.RealizationError.PackageNotFound;
            }

            // Clone package with spec
            try self.clonePackageWithSpec(env_mountpoint, pkg_dataset, pkg.id, spec);

            try package_ids.append(.{
                .name = try self.allocator.dupe(u8, pkg.id.name),
                .version = pkg.id.version,
                .revision = pkg.id.revision,
                .build_id = try self.allocator.dupe(u8, pkg.id.build_id),
            });
        }

        // Create activation script
        try self.createActivationScript(env_mountpoint, env_name);

        // Snapshot the environment
        std.debug.print("\nCreating snapshot...\n", .{});
        try self.zfs_handle.snapshot(self.allocator, env_dataset, "initial", false);

        std.debug.print("\n Environment '{s}' realized successfully\n", .{env_name});
        std.debug.print("  Location: {s}\n", .{env_mountpoint});

        return realization.Environment{
            .name = try self.allocator.dupe(u8, env_name),
            .profile_name = try self.allocator.dupe(u8, lock.profile_name),
            .dataset_path = try self.allocator.dupe(u8, env_dataset),
            .packages = try package_ids.toOwnedSlice(),
            .active = false,
        };
    }

    /// Clone a package into the environment with spec
    fn clonePackageWithSpec(
        self: *UserRealizationEngine,
        env_mountpoint: []const u8,
        pkg_dataset: []const u8,
        pkg_id: PackageId,
        spec: *const RealizationSpec,
    ) !void {
        _ = pkg_id;

        // Get package mountpoint
        const pkg_mountpoint = try self.zfs_handle.getMountpoint(
            self.allocator,
            pkg_dataset,
        );
        defer self.allocator.free(pkg_mountpoint);

        // Package files are in root/ subdirectory
        const pkg_root = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ pkg_mountpoint, "root" },
        );
        defer self.allocator.free(pkg_root);

        // Use spec's merge strategy
        switch (spec.default_strategy) {
            .symlink => {
                // Use symlinks for space efficiency
                const cmd = try std.fmt.allocPrint(
                    self.allocator,
                    "cp -R -s -n {s}/. {s}/",
                    .{ pkg_root, env_mountpoint },
                );
                defer self.allocator.free(cmd);
                try self.runShellCommand(cmd);
            },
            .hardlink => {
                // Use hard links for shared data
                const cmd = try std.fmt.allocPrint(
                    self.allocator,
                    "cp -R -l -n {s}/. {s}/",
                    .{ pkg_root, env_mountpoint },
                );
                defer self.allocator.free(cmd);
                try self.runShellCommand(cmd);
            },
            .copy => {
                // Full copy for isolation
                const cmd = try std.fmt.allocPrint(
                    self.allocator,
                    "cp -R -n {s}/. {s}/",
                    .{ pkg_root, env_mountpoint },
                );
                defer self.allocator.free(cmd);
                try self.runShellCommand(cmd);
            },
            .zfs_clone => {
                // ZFS clone not supported for user environments
                // Fall back to symlink
                const cmd = try std.fmt.allocPrint(
                    self.allocator,
                    "cp -R -s -n {s}/. {s}/",
                    .{ pkg_root, env_mountpoint },
                );
                defer self.allocator.free(cmd);
                try self.runShellCommand(cmd);
            },
        }
    }

    /// Run a shell command
    fn runShellCommand(self: *UserRealizationEngine, cmd: []const u8) !void {
        var child = std.process.Child.init(&[_][]const u8{ "sh", "-c", cmd }, self.allocator);
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Pipe;

        try child.spawn();
        const stderr = try child.stderr.?.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(stderr);

        const term = try child.wait();
        if (term.Exited != 0 and stderr.len > 0) {
            std.debug.print("    Warning: {s}\n", .{stderr});
        }
    }

    /// Create activation script for the environment
    fn createActivationScript(
        self: *UserRealizationEngine,
        env_mountpoint: []const u8,
        env_name: []const u8,
    ) !void {
        const script_path = try std.fs.path.join(
            self.allocator,
            &[_][]const u8{ env_mountpoint, "activate" },
        );
        defer self.allocator.free(script_path);

        const file = try std.fs.cwd().createFile(script_path, .{ .mode = 0o755 });
        defer file.close();

        const writer = file.writer();

        try writer.writeAll("#!/bin/sh\n");
        try writer.writeAll("# Axiom user environment activation script\n");
        try writer.print("# Environment: {s}\n", .{env_name});
        try writer.print("# User: {s}\n\n", .{self.user_ctx.username});

        try writer.print("export AXIOM_ENV=\"{s}\"\n", .{env_name});
        try writer.print("export AXIOM_USER=\"{s}\"\n", .{self.user_ctx.username});
        try writer.print("export PATH=\"{s}/bin:$PATH\"\n", .{env_mountpoint});
        try writer.print("export LD_LIBRARY_PATH=\"{s}/lib:$LD_LIBRARY_PATH\"\n", .{env_mountpoint});
        try writer.print("export MANPATH=\"{s}/share/man:$MANPATH\"\n", .{env_mountpoint});

        try writer.writeAll("\necho \"Axiom user environment '");
        try writer.writeAll(env_name);
        try writer.writeAll("' activated\"\n");
        try writer.writeAll("echo \"To deactivate, run: deactivate\"\n\n");

        try writer.writeAll("deactivate() {\n");
        try writer.writeAll("  unset AXIOM_ENV\n");
        try writer.writeAll("  unset AXIOM_USER\n");
        try writer.writeAll("  echo \"Environment deactivated\"\n");
        try writer.writeAll("}\n");
    }

    /// Activate an environment
    pub fn activate(self: *UserRealizationEngine, env_name: []const u8) !void {
        const env_root = try self.getUserEnvRoot();
        defer self.allocator.free(env_root);

        const env_dataset = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ env_root, env_name },
        );
        defer self.allocator.free(env_dataset);

        const exists = try self.zfs_handle.datasetExists(
            self.allocator,
            env_dataset,
            .filesystem,
        );

        if (!exists) {
            return realization.RealizationError.EnvironmentNotFound;
        }

        std.debug.print("Activating user environment: {s}\n", .{env_name});

        const env_mountpoint = try self.zfs_handle.getMountpoint(
            self.allocator,
            env_dataset,
        );
        defer self.allocator.free(env_mountpoint);

        std.debug.print("  Mountpoint: {s}\n", .{env_mountpoint});
        std.debug.print("\nTo activate in your shell, run:\n", .{});
        std.debug.print("  source {s}/activate\n", .{env_mountpoint});
    }

    /// Destroy a user environment
    pub fn destroy(self: *UserRealizationEngine, env_name: []const u8) !void {
        const env_root = try self.getUserEnvRoot();
        defer self.allocator.free(env_root);

        const env_dataset = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ env_root, env_name },
        );
        defer self.allocator.free(env_dataset);

        std.debug.print("Destroying user environment: {s}\n", .{env_name});

        try self.zfs_handle.destroyDataset(self.allocator, env_dataset, true);

        std.debug.print("  Environment destroyed\n", .{});
    }

    /// List user environments
    pub fn listEnvironments(self: *UserRealizationEngine) ![][]const u8 {
        const env_root = try self.getUserEnvRoot();
        defer self.allocator.free(env_root);

        const exists = try self.zfs_handle.datasetExists(
            self.allocator,
            env_root,
            .filesystem,
        );

        if (!exists) {
            return &[_][]const u8{};
        }

        return self.zfs_handle.listChildDatasets(self.allocator, env_root);
    }
};

/// Multi-user manager for coordinating user operations
pub const MultiUserManager = struct {
    allocator: std.mem.Allocator,
    zfs_handle: *ZfsHandle,
    store: *PackageStore,
    users_root: []const u8 = "zroot/axiom/users",

    /// Initialize multi-user manager
    pub fn init(
        allocator: std.mem.Allocator,
        zfs_handle: *ZfsHandle,
        pkg_store: *PackageStore,
    ) MultiUserManager {
        return MultiUserManager{
            .allocator = allocator,
            .zfs_handle = zfs_handle,
            .store = pkg_store,
        };
    }

    /// Ensure the users root dataset exists
    pub fn ensureUsersRoot(self: *MultiUserManager) !void {
        const exists = try self.zfs_handle.datasetExists(
            self.allocator,
            self.users_root,
            .filesystem,
        );

        if (!exists) {
            std.debug.print("Creating users root dataset...\n", .{});
            try self.zfs_handle.createDataset(self.allocator, self.users_root, .{
                .compression = "lz4",
                .atime = false,
            });
        }
    }

    /// List all users with Axiom data
    pub fn listUsers(self: *MultiUserManager) ![][]const u8 {
        return self.zfs_handle.listChildDatasets(self.allocator, self.users_root);
    }

    /// Get disk usage for a specific user
    pub fn getUserUsage(self: *MultiUserManager, username: []const u8) !u64 {
        const user_dataset = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.users_root, username },
        );
        defer self.allocator.free(user_dataset);

        // Get used property from ZFS
        return self.zfs_handle.getDatasetUsed(self.allocator, user_dataset);
    }

    /// Remove all data for a user (admin operation)
    pub fn removeUser(self: *MultiUserManager, admin_ctx: UserContext, username: []const u8) !void {
        // Only root can remove user data
        if (!admin_ctx.isRoot()) {
            return UserError.PermissionDenied;
        }

        const user_dataset = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.users_root, username },
        );
        defer self.allocator.free(user_dataset);

        std.debug.print("Removing all Axiom data for user: {s}\n", .{username});

        try self.zfs_handle.destroyDataset(self.allocator, user_dataset, true);

        std.debug.print("  User data removed\n", .{});
    }
};
