// Boot Environment Support for Axiom System Manager
// Provides ZFS boot environment management for atomic system upgrades

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Boot environment information
pub const BootEnvironment = struct {
    name: []const u8,
    active: bool,
    active_on_reboot: bool,
    mountpoint: ?[]const u8,
    space_used: u64,
    creation_time: i64,

    pub fn deinit(self: *BootEnvironment, allocator: Allocator) void {
        allocator.free(self.name);
        if (self.mountpoint) |mp| {
            allocator.free(mp);
        }
    }
};

/// Boot environment creation options
pub const CreateOptions = struct {
    /// Source boot environment (null = current)
    source: ?[]const u8 = null,
    /// Activate immediately after creation
    activate: bool = false,
    /// Description/comment for the BE
    description: ?[]const u8 = null,
};

/// Boot environment activation options
pub const ActivateOptions = struct {
    /// Activate temporarily (only for next boot)
    temporary: bool = false,
};

/// Retention policy for automatic BE management
pub const RetentionPolicy = struct {
    /// Maximum number of boot environments to keep
    max_count: ?u32 = null,
    /// Maximum age in days
    max_age_days: ?u32 = null,
    /// Patterns to never delete (glob patterns)
    keep_patterns: []const []const u8 = &.{},
    /// Always keep the active BE
    keep_active: bool = true,
    /// Always keep BEs activated on reboot
    keep_activated: bool = true,
};

/// Result of a boot environment command
pub const CommandResult = struct {
    success: bool,
    stdout: []const u8,
    stderr: []const u8,
    exit_code: u8,

    pub fn deinit(self: *CommandResult, allocator: Allocator) void {
        if (self.stdout.len > 0) allocator.free(self.stdout);
        if (self.stderr.len > 0) allocator.free(self.stderr);
    }
};

/// Boot environment manager
pub const BootEnvManager = struct {
    allocator: Allocator,
    /// ZFS pool for boot environments (usually zroot)
    pool: []const u8,
    /// BE dataset path (usually zroot/ROOT)
    be_root: []const u8,

    const Self = @This();

    /// Initialize a new boot environment manager
    pub fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .pool = "zroot",
            .be_root = "zroot/ROOT",
        };
    }

    /// Initialize with custom pool configuration
    pub fn initWithPool(allocator: Allocator, pool: []const u8, be_root: []const u8) Self {
        return Self{
            .allocator = allocator,
            .pool = pool,
            .be_root = be_root,
        };
    }

    /// List all boot environments
    pub fn list(self: *Self) ![]BootEnvironment {
        var envs = std.ArrayList(BootEnvironment).init(self.allocator);
        errdefer {
            for (envs.items) |*env| {
                env.deinit(self.allocator);
            }
            envs.deinit();
        }

        // Run bectl list with parseable output
        var result = try self.runBectl(&[_][]const u8{ "list", "-H" });
        defer result.deinit(self.allocator);

        if (!result.success) {
            return error.BectlFailed;
        }

        // Parse output: name active mountpoint space created
        var lines = std.mem.splitScalar(u8, result.stdout, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;

            var fields = std.mem.splitScalar(u8, line, '\t');

            const name_field = fields.next() orelse continue;
            const active_field = fields.next() orelse continue;
            const mountpoint_field = fields.next() orelse continue;
            const space_field = fields.next() orelse continue;
            const created_field = fields.next() orelse continue;

            const name = try self.allocator.dupe(u8, name_field);
            errdefer self.allocator.free(name);

            const mountpoint: ?[]const u8 = if (std.mem.eql(u8, mountpoint_field, "-"))
                null
            else
                try self.allocator.dupe(u8, mountpoint_field);

            const env = BootEnvironment{
                .name = name,
                .active = std.mem.indexOf(u8, active_field, "N") != null,
                .active_on_reboot = std.mem.indexOf(u8, active_field, "R") != null,
                .mountpoint = mountpoint,
                .space_used = parseSize(space_field),
                .creation_time = parseTimestamp(created_field),
            };

            try envs.append(env);
        }

        return envs.toOwnedSlice();
    }

    /// Get the currently active boot environment
    pub fn getActive(self: *Self) !?BootEnvironment {
        const envs = try self.list();
        defer {
            for (@constCast(envs)) |*env| {
                env.deinit(self.allocator);
            }
            self.allocator.free(envs);
        }

        for (envs) |env| {
            if (env.active) {
                // Clone the active environment
                const name = try self.allocator.dupe(u8, env.name);
                errdefer self.allocator.free(name);

                const mountpoint = if (env.mountpoint) |mp|
                    try self.allocator.dupe(u8, mp)
                else
                    null;

                return BootEnvironment{
                    .name = name,
                    .active = env.active,
                    .active_on_reboot = env.active_on_reboot,
                    .mountpoint = mountpoint,
                    .space_used = env.space_used,
                    .creation_time = env.creation_time,
                };
            }
        }

        return null;
    }

    /// Create a new boot environment
    pub fn create(self: *Self, name: []const u8, options: CreateOptions) !void {
        var args = std.ArrayList([]const u8).init(self.allocator);
        defer args.deinit();

        try args.append("create");

        // Add source if specified
        if (options.source) |source| {
            try args.append("-e");
            try args.append(source);
        }

        try args.append(name);

        var result = try self.runBectl(args.items);
        defer result.deinit(self.allocator);

        if (!result.success) {
            std.log.err("Failed to create boot environment: {s}", .{result.stderr});
            return error.CreateFailed;
        }

        // Activate if requested
        if (options.activate) {
            try self.activate(name, .{});
        }
    }

    /// Create a boot environment with automatic timestamp naming
    pub fn createTimestamped(self: *Self, prefix: []const u8, options: CreateOptions) ![]const u8 {
        const timestamp = std.time.timestamp();
        const datetime = epochToDatetime(timestamp);

        const name = try std.fmt.allocPrint(
            self.allocator,
            "{s}-{d:0>4}{d:0>2}{d:0>2}-{d:0>2}{d:0>2}{d:0>2}",
            .{
                prefix,
                datetime.year,
                datetime.month,
                datetime.day,
                datetime.hour,
                datetime.minute,
                datetime.second,
            },
        );
        errdefer self.allocator.free(name);

        try self.create(name, options);
        return name;
    }

    /// Activate a boot environment
    pub fn activate(self: *Self, name: []const u8, options: ActivateOptions) !void {
        var args = std.ArrayList([]const u8).init(self.allocator);
        defer args.deinit();

        try args.append("activate");

        if (options.temporary) {
            try args.append("-t");
        }

        try args.append(name);

        var result = try self.runBectl(args.items);
        defer result.deinit(self.allocator);

        if (!result.success) {
            std.log.err("Failed to activate boot environment: {s}", .{result.stderr});
            return error.ActivateFailed;
        }
    }

    /// Destroy a boot environment
    pub fn destroy(self: *Self, name: []const u8, force: bool) !void {
        // Safety check: don't destroy active BE
        const active = try self.getActive();
        if (active) |a| {
            defer @constCast(&a).deinit(self.allocator);
            if (std.mem.eql(u8, a.name, name)) {
                return error.CannotDestroyActive;
            }
        }

        var args = std.ArrayList([]const u8).init(self.allocator);
        defer args.deinit();

        try args.append("destroy");

        if (force) {
            try args.append("-F");
        }

        try args.append(name);

        var result = try self.runBectl(args.items);
        defer result.deinit(self.allocator);

        if (!result.success) {
            std.log.err("Failed to destroy boot environment: {s}", .{result.stderr});
            return error.DestroyFailed;
        }
    }

    /// Rename a boot environment
    pub fn rename(self: *Self, old_name: []const u8, new_name: []const u8) !void {
        var result = try self.runBectl(&[_][]const u8{ "rename", old_name, new_name });
        defer result.deinit(self.allocator);

        if (!result.success) {
            std.log.err("Failed to rename boot environment: {s}", .{result.stderr});
            return error.RenameFailed;
        }
    }

    /// Mount a boot environment
    pub fn mount(self: *Self, name: []const u8, mountpoint: ?[]const u8) ![]const u8 {
        var args = std.ArrayList([]const u8).init(self.allocator);
        defer args.deinit();

        try args.append("mount");
        try args.append(name);

        if (mountpoint) |mp| {
            try args.append(mp);
        }

        var result = try self.runBectl(args.items);
        defer result.deinit(self.allocator);

        if (!result.success) {
            std.log.err("Failed to mount boot environment: {s}", .{result.stderr});
            return error.MountFailed;
        }

        // Return the mountpoint (either specified or from output)
        if (mountpoint) |mp| {
            return try self.allocator.dupe(u8, mp);
        }

        // Parse mountpoint from bectl output
        const trimmed = std.mem.trim(u8, result.stdout, " \t\n\r");
        if (trimmed.len > 0) {
            return try self.allocator.dupe(u8, trimmed);
        }

        // Default mountpoint pattern
        return try std.fmt.allocPrint(self.allocator, "/tmp/be_mount.{s}", .{name});
    }

    /// Unmount a boot environment
    pub fn unmount(self: *Self, name: []const u8, force: bool) !void {
        var args = std.ArrayList([]const u8).init(self.allocator);
        defer args.deinit();

        try args.append("unmount");

        if (force) {
            try args.append("-f");
        }

        try args.append(name);

        var result = try self.runBectl(args.items);
        defer result.deinit(self.allocator);

        if (!result.success) {
            std.log.err("Failed to unmount boot environment: {s}", .{result.stderr});
            return error.UnmountFailed;
        }
    }

    /// Rollback to the previously active boot environment
    pub fn rollback(self: *Self) ![]const u8 {
        // Find the BE that was active on reboot but isn't currently active
        const envs = try self.list();
        defer {
            for (@constCast(envs)) |*env| {
                env.deinit(self.allocator);
            }
            self.allocator.free(envs);
        }

        var current_active: ?[]const u8 = null;
        var previous_be: ?[]const u8 = null;
        var newest_time: i64 = 0;

        for (envs) |env| {
            if (env.active) {
                current_active = env.name;
            } else if (env.active_on_reboot and !env.active) {
                // This BE is set for reboot but not currently running
                previous_be = env.name;
            } else if (env.creation_time > newest_time and !env.active) {
                // Track newest non-active BE as fallback
                newest_time = env.creation_time;
                previous_be = env.name;
            }
        }

        const target = previous_be orelse return error.NoPreviousBE;

        // Activate the previous BE
        try self.activate(target, .{});

        return try self.allocator.dupe(u8, target);
    }

    /// Apply retention policy to boot environments
    pub fn applyRetention(self: *Self, policy: RetentionPolicy) !u32 {
        const envs = try self.list();
        defer {
            for (@constCast(envs)) |*env| {
                env.deinit(self.allocator);
            }
            self.allocator.free(envs);
        }

        var to_delete = std.ArrayList([]const u8).init(self.allocator);
        defer {
            for (to_delete.items) |name| {
                self.allocator.free(name);
            }
            to_delete.deinit();
        }

        const now = std.time.timestamp();
        const max_age_seconds: i64 = if (policy.max_age_days) |days|
            @as(i64, @intCast(days)) * 24 * 60 * 60
        else
            std.math.maxInt(i64);

        // Collect BEs that violate policy
        for (envs) |env| {
            // Skip active BE if configured
            if (policy.keep_active and env.active) continue;
            if (policy.keep_activated and env.active_on_reboot) continue;

            // Check keep patterns
            var keep = false;
            for (policy.keep_patterns) |pattern| {
                if (matchGlob(pattern, env.name)) {
                    keep = true;
                    break;
                }
            }
            if (keep) continue;

            // Check age
            const age = now - env.creation_time;
            if (age > max_age_seconds) {
                const name_copy = try self.allocator.dupe(u8, env.name);
                try to_delete.append(name_copy);
            }
        }

        // Apply max_count if specified
        if (policy.max_count) |max| {
            if (envs.len > max) {
                // Sort by creation time (oldest first) and mark excess for deletion
                // This is simplified - in production we'd sort properly
                var count: u32 = @intCast(envs.len);
                for (envs) |env| {
                    if (count <= max) break;
                    if (policy.keep_active and env.active) continue;
                    if (policy.keep_activated and env.active_on_reboot) continue;

                    // Check if already in delete list
                    var already_listed = false;
                    for (to_delete.items) |name| {
                        if (std.mem.eql(u8, name, env.name)) {
                            already_listed = true;
                            break;
                        }
                    }
                    if (!already_listed) {
                        const name_copy = try self.allocator.dupe(u8, env.name);
                        try to_delete.append(name_copy);
                        count -= 1;
                    }
                }
            }
        }

        // Delete marked BEs
        var deleted: u32 = 0;
        for (to_delete.items) |name| {
            self.destroy(name, false) catch |err| {
                std.log.warn("Failed to delete BE {s}: {}", .{ name, err });
                continue;
            };
            deleted += 1;
        }

        return deleted;
    }

    /// Check if boot environments are supported on this system
    pub fn isSupported(self: *Self) bool {
        var result = self.runBectl(&[_][]const u8{"list"}) catch return false;
        defer result.deinit(self.allocator);
        return result.success;
    }

    /// Get boot environment statistics
    pub fn getStats(self: *Self) !struct {
        total_count: u32,
        total_space: u64,
        active_name: []const u8,
    } {
        const envs = try self.list();
        defer {
            for (@constCast(envs)) |*env| {
                env.deinit(self.allocator);
            }
            self.allocator.free(envs);
        }

        var total_space: u64 = 0;
        var active_name: []const u8 = "";

        for (envs) |env| {
            total_space += env.space_used;
            if (env.active) {
                active_name = try self.allocator.dupe(u8, env.name);
            }
        }

        return .{
            .total_count = @intCast(envs.len),
            .total_space = total_space,
            .active_name = active_name,
        };
    }

    /// Run a bectl command
    fn runBectl(self: *Self, args: []const []const u8) !CommandResult {
        var full_args = std.ArrayList([]const u8).init(self.allocator);
        defer full_args.deinit();

        try full_args.append("bectl");
        for (args) |arg| {
            try full_args.append(arg);
        }

        var child = std.process.Child.init(full_args.items, self.allocator);
        child.stderr_behavior = .Pipe;
        child.stdout_behavior = .Pipe;

        try child.spawn();

        var stdout = std.ArrayList(u8).init(self.allocator);
        defer stdout.deinit();
        var stderr = std.ArrayList(u8).init(self.allocator);
        defer stderr.deinit();

        if (child.stdout) |stdout_pipe| {
            var reader = stdout_pipe.reader();
            reader.readAllArrayList(&stdout, 64 * 1024) catch {};
        }
        if (child.stderr) |stderr_pipe| {
            var reader = stderr_pipe.reader();
            reader.readAllArrayList(&stderr, 64 * 1024) catch {};
        }

        const term = try child.wait();
        const exit_code: u8 = switch (term) {
            .Exited => |code| code,
            else => 1,
        };

        return CommandResult{
            .success = exit_code == 0,
            .stdout = try stdout.toOwnedSlice(),
            .stderr = try stderr.toOwnedSlice(),
            .exit_code = exit_code,
        };
    }
};

/// Simple datetime struct for timestamp formatting
const DateTime = struct {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
};

/// Convert epoch timestamp to DateTime
fn epochToDatetime(timestamp: i64) DateTime {
    // Simplified conversion - for production use proper calendar math
    const SECONDS_PER_DAY = 86400;
    const SECONDS_PER_HOUR = 3600;
    const SECONDS_PER_MINUTE = 60;

    var remaining = timestamp;

    // Days since epoch
    const days = @divFloor(remaining, SECONDS_PER_DAY);
    remaining = @mod(remaining, SECONDS_PER_DAY);

    // Time of day
    const hour: u8 = @intCast(@divFloor(remaining, SECONDS_PER_HOUR));
    remaining = @mod(remaining, SECONDS_PER_HOUR);
    const minute: u8 = @intCast(@divFloor(remaining, SECONDS_PER_MINUTE));
    const second: u8 = @intCast(@mod(remaining, SECONDS_PER_MINUTE));

    // Calculate year/month/day from days since epoch (1970-01-01)
    var year: u16 = 1970;
    var day_count = days;

    while (true) {
        const days_in_year: i64 = if (isLeapYear(year)) 366 else 365;
        if (day_count < days_in_year) break;
        day_count -= days_in_year;
        year += 1;
    }

    const days_in_month = if (isLeapYear(year))
        [_]u8{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
    else
        [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

    var month: u8 = 1;
    for (days_in_month) |dim| {
        if (day_count < dim) break;
        day_count -= dim;
        month += 1;
    }

    return DateTime{
        .year = year,
        .month = month,
        .day = @intCast(day_count + 1),
        .hour = hour,
        .minute = minute,
        .second = second,
    };
}

fn isLeapYear(year: u16) bool {
    return (year % 4 == 0 and year % 100 != 0) or (year % 400 == 0);
}

/// Parse size string (e.g., "1.5G", "500M") to bytes
fn parseSize(size_str: []const u8) u64 {
    if (size_str.len == 0) return 0;

    const last_char = size_str[size_str.len - 1];
    const multiplier: u64 = switch (last_char) {
        'K', 'k' => 1024,
        'M', 'm' => 1024 * 1024,
        'G', 'g' => 1024 * 1024 * 1024,
        'T', 't' => 1024 * 1024 * 1024 * 1024,
        else => 1,
    };

    const num_str = if (last_char >= 'A' and last_char <= 'z')
        size_str[0 .. size_str.len - 1]
    else
        size_str;

    // Parse float and multiply
    const value = std.fmt.parseFloat(f64, num_str) catch return 0;
    return @intFromFloat(value * @as(f64, @floatFromInt(multiplier)));
}

/// Parse timestamp string to epoch
fn parseTimestamp(ts_str: []const u8) i64 {
    // bectl outputs timestamps in various formats
    // This is a simplified parser
    _ = ts_str;
    return std.time.timestamp();
}

/// Simple glob pattern matching
fn matchGlob(pattern: []const u8, text: []const u8) bool {
    var p_idx: usize = 0;
    var t_idx: usize = 0;
    var star_p: ?usize = null;
    var star_t: usize = 0;

    while (t_idx < text.len) {
        if (p_idx < pattern.len and (pattern[p_idx] == '?' or pattern[p_idx] == text[t_idx])) {
            p_idx += 1;
            t_idx += 1;
        } else if (p_idx < pattern.len and pattern[p_idx] == '*') {
            star_p = p_idx;
            star_t = t_idx;
            p_idx += 1;
        } else if (star_p != null) {
            p_idx = star_p.? + 1;
            star_t += 1;
            t_idx = star_t;
        } else {
            return false;
        }
    }

    while (p_idx < pattern.len and pattern[p_idx] == '*') {
        p_idx += 1;
    }

    return p_idx == pattern.len;
}

/// Integration with system upgrades
pub const SystemUpgradeOptions = struct {
    /// Create a boot environment before upgrade
    create_be: bool = true,
    /// Name prefix for auto-created BE
    be_prefix: []const u8 = "pre-upgrade",
    /// Activate the new BE after upgrade
    activate_after: bool = true,
    /// Retention policy for upgrade BEs
    retention: ?RetentionPolicy = null,
};

/// Boot environment hooks for system operations
pub const BeHooks = struct {
    allocator: Allocator,
    manager: *BootEnvManager,
    auto_snapshot: bool,
    snapshot_prefix: []const u8,

    const Self = @This();

    pub fn init(allocator: Allocator, manager: *BootEnvManager) Self {
        return Self{
            .allocator = allocator,
            .manager = manager,
            .auto_snapshot = true,
            .snapshot_prefix = "auto",
        };
    }

    /// Called before system modification
    pub fn beforeSystemChange(self: *Self, description: []const u8) !?[]const u8 {
        if (!self.auto_snapshot) return null;

        // Create a pre-change snapshot
        const prefix = try std.fmt.allocPrint(
            self.allocator,
            "{s}-{s}",
            .{ self.snapshot_prefix, description },
        );
        defer self.allocator.free(prefix);

        const be_name = try self.manager.createTimestamped(prefix, .{});
        std.log.info("Created boot environment snapshot: {s}", .{be_name});
        return be_name;
    }

    /// Called after successful system modification
    pub fn afterSystemChange(self: *Self, be_name: ?[]const u8) void {
        _ = self;
        if (be_name) |name| {
            std.log.info("System change successful, rollback available: {s}", .{name});
        }
    }

    /// Called after failed system modification
    pub fn onSystemChangeFailed(self: *Self, be_name: ?[]const u8) !void {
        if (be_name) |name| {
            std.log.warn("System change failed, rolling back to: {s}", .{name});
            try self.manager.activate(name, .{});
        }
    }
};

// Tests
test "parse size strings" {
    try std.testing.expectEqual(@as(u64, 1024), parseSize("1K"));
    try std.testing.expectEqual(@as(u64, 1048576), parseSize("1M"));
    try std.testing.expectEqual(@as(u64, 1073741824), parseSize("1G"));
    try std.testing.expectEqual(@as(u64, 1536 * 1024 * 1024), parseSize("1.5G"));
}

test "glob matching" {
    try std.testing.expect(matchGlob("*", "anything"));
    try std.testing.expect(matchGlob("pre-*", "pre-upgrade"));
    try std.testing.expect(matchGlob("*-backup", "system-backup"));
    try std.testing.expect(matchGlob("test-?", "test-1"));
    try std.testing.expect(!matchGlob("test-?", "test-12"));
    try std.testing.expect(matchGlob("*upgrade*", "pre-upgrade-20241201"));
}

test "epoch to datetime" {
    // Test a known timestamp: 2024-01-15 12:30:45 UTC = 1705321845
    const dt = epochToDatetime(1705321845);
    try std.testing.expectEqual(@as(u16, 2024), dt.year);
    try std.testing.expectEqual(@as(u8, 1), dt.month);
    try std.testing.expectEqual(@as(u8, 15), dt.day);
    try std.testing.expectEqual(@as(u8, 12), dt.hour);
    try std.testing.expectEqual(@as(u8, 30), dt.minute);
    try std.testing.expectEqual(@as(u8, 45), dt.second);
}
