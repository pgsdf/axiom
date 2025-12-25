const std = @import("std");
const user_pkg = @import("user.zig");

const Allocator = std.mem.Allocator;

/// User identity for access control
pub const User = struct {
    uid: u32,
    gid: u32,
    username: []const u8,
    groups: []const u32,
    home_dir: []const u8,

    pub fn isRoot(self: *const User) bool {
        return self.uid == 0;
    }

    pub fn inGroup(self: *const User, gid: u32) bool {
        if (self.gid == gid) return true;
        for (self.groups) |g| {
            if (g == gid) return true;
        }
        return false;
    }

    pub fn deinit(self: *User, allocator: Allocator) void {
        allocator.free(self.username);
        allocator.free(self.home_dir);
        if (self.groups.len > 0) {
            allocator.free(self.groups);
        }
    }
};

/// Store operation types
pub const StoreOp = enum {
    read,
    import_pkg,
    gc,
    modify_metadata,
    create_profile,
    delete_profile,

    pub fn toString(self: StoreOp) []const u8 {
        return switch (self) {
            .read => "read",
            .import_pkg => "import",
            .gc => "gc",
            .modify_metadata => "modify_metadata",
            .create_profile => "create_profile",
            .delete_profile => "delete_profile",
        };
    }

    pub fn requiresRoot(self: StoreOp) bool {
        return switch (self) {
            .read => false,
            .import_pkg => true,
            .gc => true,
            .modify_metadata => true,
            .create_profile => true,
            .delete_profile => true,
        };
    }
};

/// User space operation types
pub const UserSpaceOp = enum {
    read_profile,
    write_profile,
    create_env,
    delete_env,
    activate_env,

    pub fn toString(self: UserSpaceOp) []const u8 {
        return switch (self) {
            .read_profile => "read_profile",
            .write_profile => "write_profile",
            .create_env => "create_env",
            .delete_env => "delete_env",
            .activate_env => "activate_env",
        };
    }
};

/// Access policy configuration
pub const AccessPolicy = struct {
    store_owner: u32 = 0,
    store_group: u32 = 0,
    store_mode: u16 = 0o755,
    user_template_mode: u16 = 0o700,
    allow_user_imports: bool = false,
    require_signature_for_setuid: bool = true,
    audit_setuid: bool = true,

    pub fn default() AccessPolicy {
        return .{};
    }
};

/// Setuid binary definition
pub const SetuidBinary = struct {
    path: []const u8,
    owner: u32 = 0,
    group: u32 = 0,
    mode: u16 = 0o4755,
    audit: bool = true,

    pub fn deinit(self: *SetuidBinary, allocator: Allocator) void {
        allocator.free(self.path);
    }
};

/// Setuid policy configuration
pub const SetuidPolicy = struct {
    allowed_binaries: std.ArrayList([]const u8),
    deny_unknown: bool = true,
    require_signature: bool = true,

    pub fn init(_allocator: Allocator) SetuidPolicy {
        return .{
            .allowed_binaries = .empty,
        };
    }

    pub fn deinit(self: *SetuidPolicy, allocator: Allocator) void {
        for (self.allowed_binaries.items) |b| {
            allocator.free(b);
        }
        self.allowed_binaries.deinit(allocator);
    }

    pub fn isAllowed(self: *const SetuidPolicy, binary_name: []const u8) bool {
        for (self.allowed_binaries.items) |allowed| {
            if (std.mem.eql(u8, allowed, binary_name)) {
                return true;
            }
        }
        return !self.deny_unknown;
    }
};

/// Setuid validation result
pub const SetuidValidationResult = struct {
    valid: bool,
    issues: std.ArrayList([]const u8),

    pub fn init(_allocator: Allocator) SetuidValidationResult {
        return .{
            .valid = true,
            .issues = .empty,
        };
    }

    pub fn deinit(self: *SetuidValidationResult, allocator: Allocator) void {
        for (self.issues.items) |issue| {
            allocator.free(issue);
        }
        self.issues.deinit(allocator);
    }

    pub fn addIssue(self: *SetuidValidationResult, allocator: Allocator, issue: []const u8) !void {
        self.valid = false;
        try self.issues.append(allocator, try allocator.dupe(u8, issue));
    }
};

/// Audit log entry
pub const AuditEntry = struct {
    timestamp: i64,
    user_uid: u32,
    username: []const u8,
    binary_path: []const u8,
    action: []const u8,
    success: bool,

    pub fn deinit(self: *AuditEntry, allocator: Allocator) void {
        allocator.free(self.username);
        allocator.free(self.binary_path);
        allocator.free(self.action);
    }
};

/// Access Control Manager
pub const AccessControl = struct {
    allocator: Allocator,
    policy: AccessPolicy,
    axiom_gid: u32,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .policy = AccessPolicy.default(),
            .axiom_gid = 0, // Would be looked up from /etc/group
        };
    }

    pub fn setPolicy(self: *Self, policy: AccessPolicy) void {
        self.policy = policy;
    }

    /// Check if user can perform store operation
    pub fn checkStoreAccess(self: *Self, user: *const User, operation: StoreOp) !bool {
        // Root can do anything
        if (user.isRoot()) {
            return true;
        }

        // Check if operation requires root
        if (operation.requiresRoot()) {
            return false;
        }

        // For read operations, check if user is in axiom group
        if (operation == .read) {
            return user.inGroup(self.axiom_gid) or self.policy.store_mode & 0o004 != 0;
        }

        return false;
    }

    /// Check if user can access another user's space
    pub fn checkUserSpace(self: *Self, user: *const User, target_uid: u32, operation: UserSpaceOp) !bool {
        _ = self;

        // Root can access any user space
        if (user.isRoot()) {
            return true;
        }

        // Users can only access their own space
        if (user.uid != target_uid) {
            return false;
        }

        // All operations allowed on own space
        _ = operation;
        return true;
    }

    /// Get effective policy for user
    pub fn getEffectivePolicy(self: *Self, user: *const User) AccessPolicy {
        var policy = self.policy;

        // Non-root users cannot import
        if (!user.isRoot()) {
            policy.allow_user_imports = false;
        }

        return policy;
    }

    /// Initialize user space directory structure
    pub fn initUserSpace(self: *Self, user: *const User) !void {
        const user_base = try std.fmt.allocPrint(
            self.allocator,
            "/axiom/users/{s}",
            .{user.username},
        );
        defer self.allocator.free(user_base);

        // Create directories
        const dirs = [_][]const u8{
            "profiles",
            "env",
            ".config",
        };

        for (dirs) |subdir| {
            const path = try std.fmt.allocPrint(
                self.allocator,
                "{s}/{s}",
                .{ user_base, subdir },
            );
            defer self.allocator.free(path);

            std.fs.cwd().makePath(path) catch |err| {
                if (err != error.PathAlreadyExists) return err;
            };
        }
    }
};

/// Setuid Binary Manager
pub const SetuidManager = struct {
    allocator: Allocator,
    policy: SetuidPolicy,
    audit_log_path: []const u8,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .policy = SetuidPolicy.empty,
            .audit_log_path = "/var/log/axiom-setuid.log",
        };
    }

    pub fn deinit(self: *Self) void {
        self.policy.deinit(self.allocator);
    }

    pub fn setPolicy(self: *Self, policy: SetuidPolicy) void {
        self.policy.deinit(self.allocator);
        self.policy = policy;
    }

    /// Validate setuid binary against policy
    pub fn validateSetuid(
        self: *Self,
        binary: *const SetuidBinary,
        has_signature: bool,
    ) !SetuidValidationResult {
        var result = SetuidValidationResult.init(self.allocator);

        // Extract binary name from path
        const binary_name = std.fs.path.basename(binary.path);

        // Check if binary is in allowed list
        if (!self.policy.isAllowed(binary_name)) {
            try result.addIssue(self.allocator, "Binary not in allowed setuid list");
        }

        // Check signature requirement
        if (self.policy.require_signature and !has_signature) {
            try result.addIssue(self.allocator, "Setuid binary requires signature but none provided");
        }

        // Check owner is root
        if (binary.owner != 0) {
            try result.addIssue(self.allocator, "Setuid binary must be owned by root");
        }

        return result;
    }

    /// Install setuid binary with proper permissions
    pub fn installSetuid(
        self: *Self,
        src_path: []const u8,
        dst_path: []const u8,
        binary: *const SetuidBinary,
    ) !void {
        // Copy file
        try std.fs.cwd().copyFile(src_path, std.fs.cwd(), dst_path, .{});

        // Set ownership (would use chown syscall)
        _ = binary;

        // Log installation
        try self.auditLog("install", dst_path, 0, true);
    }

    /// Audit setuid execution
    pub fn auditSetuidExecution(
        self: *Self,
        binary_path: []const u8,
        user: *const User,
        success: bool,
    ) !void {
        if (!self.policy.require_signature) {
            return; // Auditing disabled
        }

        try self.auditLog("execute", binary_path, user.uid, success);
    }

    fn auditLog(
        self: *Self,
        action: []const u8,
        binary_path: []const u8,
        uid: u32,
        success: bool,
    ) !void {
        const file = std.fs.cwd().createFile(self.audit_log_path, .{
            .truncate = false,
        }) catch return;
        defer file.close();

        file.seekFromEnd(0) catch return;

        const timestamp = std.time.timestamp();
        const status = if (success) "SUCCESS" else "FAILED";

        const entry = try std.fmt.allocPrint(
            self.allocator,
            "{d} uid={d} action={s} binary={s} status={s}\n",
            .{ timestamp, uid, action, binary_path, status },
        );
        defer self.allocator.free(entry);

        file.writeAll(entry) catch {};
    }

    /// Read audit log entries
    pub fn readAuditLog(self: *Self, limit: usize) ![]AuditEntry {
        var entries: std.ArrayList(AuditEntry) = .empty;

        const file = std.fs.cwd().openFile(self.audit_log_path, .{}) catch {
            return entries.toOwnedSlice(self.allocator);
        };
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 10 * 1024 * 1024);
        defer self.allocator.free(content);

        var lines = std.mem.splitScalar(u8, content, '\n');
        var count: usize = 0;

        while (lines.next()) |line| {
            if (line.len == 0) continue;
            if (count >= limit) break;

            // Parse log entry (simplified)
            var entry = AuditEntry{
                .timestamp = 0,
                .user_uid = 0,
                .username = try self.allocator.dupe(u8, "unknown"),
                .binary_path = try self.allocator.dupe(u8, "unknown"),
                .action = try self.allocator.dupe(u8, "unknown"),
                .success = true,
            };

            // Extract fields from log line
            if (std.mem.indexOf(u8, line, "binary=")) |pos| {
                const start = pos + 7;
                var end = start;
                while (end < line.len and line[end] != ' ') {
                    end += 1;
                }
                self.allocator.free(entry.binary_path);
                entry.binary_path = try self.allocator.dupe(u8, line[start..end]);
            }

            if (std.mem.indexOf(u8, line, "action=")) |pos| {
                const start = pos + 7;
                var end = start;
                while (end < line.len and line[end] != ' ') {
                    end += 1;
                }
                self.allocator.free(entry.action);
                entry.action = try self.allocator.dupe(u8, line[start..end]);
            }

            if (std.mem.indexOf(u8, line, "FAILED")) |_| {
                entry.success = false;
            }

            try entries.append(self.allocator, entry);
            count += 1;
        }

        return entries.toOwnedSlice(self.allocator);
    }
};

/// Privilege level for operations
pub const PrivilegeLevel = enum {
    root_only,
    user_with_group,
    any_user,

    pub fn toString(self: PrivilegeLevel) []const u8 {
        return switch (self) {
            .root_only => "root only",
            .user_with_group => "user with axiom group",
            .any_user => "any user",
        };
    }
};

/// Operation privilege requirements
pub const OperationPrivilege = struct {
    operation: []const u8,
    level: PrivilegeLevel,
    description: []const u8,
};

/// Get privilege requirements for all operations
pub fn getPrivilegeTable() []const OperationPrivilege {
    return &[_]OperationPrivilege{
        // Root only operations
        .{ .operation = "import", .level = .root_only, .description = "Import packages to store" },
        .{ .operation = "system-gc", .level = .root_only, .description = "Garbage collect shared store" },
        .{ .operation = "profile-create", .level = .root_only, .description = "Create system profile" },
        .{ .operation = "profile-delete", .level = .root_only, .description = "Delete system profile" },
        .{ .operation = "setuid-install", .level = .root_only, .description = "Install setuid binaries" },

        // User with group membership
        .{ .operation = "store-read", .level = .user_with_group, .description = "Read from package store" },
        .{ .operation = "cache-fetch", .level = .user_with_group, .description = "Fetch from binary cache" },

        // Per-user operations (no root)
        .{ .operation = "user-profile-create", .level = .any_user, .description = "Create user profile" },
        .{ .operation = "user-profile-delete", .level = .any_user, .description = "Delete user profile" },
        .{ .operation = "user-realize", .level = .any_user, .description = "Realize user environment" },
        .{ .operation = "user-activate", .level = .any_user, .description = "Activate user environment" },
        .{ .operation = "user-env-list", .level = .any_user, .description = "List user environments" },
    };
}

/// User space layout paths
pub const UserSpaceLayout = struct {
    allocator: Allocator,
    username: []const u8,
    base_path: []const u8,

    const Self = @This();

    pub fn init(allocator: Allocator, username: []const u8) !Self {
        const base = try std.fmt.allocPrint(allocator, "/axiom/users/{s}", .{username});
        return .{
            .allocator = allocator,
            .username = try allocator.dupe(u8, username),
            .base_path = base,
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.username);
        self.allocator.free(self.base_path);
    }

    pub fn profilesDir(self: *const Self) ![]const u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/profiles", .{self.base_path});
    }

    pub fn envDir(self: *const Self) ![]const u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/env", .{self.base_path});
    }

    pub fn configDir(self: *const Self) ![]const u8 {
        return std.fmt.allocPrint(self.allocator, "{s}/.config", .{self.base_path});
    }
};

/// Group-based profile sharing
pub const SharedGroup = struct {
    name: []const u8,
    gid: u32,
    members: []const []const u8,
    shared_profiles: []const []const u8,

    pub fn deinit(self: *SharedGroup, allocator: Allocator) void {
        allocator.free(self.name);
        for (self.members) |m| allocator.free(m);
        if (self.members.len > 0) allocator.free(self.members);
        for (self.shared_profiles) |p| allocator.free(p);
        if (self.shared_profiles.len > 0) allocator.free(self.shared_profiles);
    }

    pub fn isMember(self: *const SharedGroup, username: []const u8) bool {
        for (self.members) |member| {
            if (std.mem.eql(u8, member, username)) {
                return true;
            }
        }
        return false;
    }
};

// Tests
test "AccessControl.checkStoreAccess" {
    var ac = AccessControl.init(std.testing.allocator);

    var root_user = User{
        .uid = 0,
        .gid = 0,
        .username = "root",
        .groups = &[_]u32{},
        .home_dir = "/root",
    };

    const can_import = try ac.checkStoreAccess(&root_user, .import_pkg);
    try std.testing.expect(can_import);
}

test "SetuidPolicy.isAllowed" {
    const allocator = std.testing.allocator;
    var policy = SetuidPolicy.empty;
    defer policy.deinit(allocator);

    try policy.allowed_binaries.append(try allocator.dupe(u8, "sudo"));

    try std.testing.expect(policy.isAllowed("sudo"));
    try std.testing.expect(!policy.isAllowed("unknown"));
}

test "User.isRoot" {
    const root = User{
        .uid = 0,
        .gid = 0,
        .username = "root",
        .groups = &[_]u32{},
        .home_dir = "/root",
    };

    const alice = User{
        .uid = 1000,
        .gid = 1000,
        .username = "alice",
        .groups = &[_]u32{},
        .home_dir = "/home/alice",
    };

    try std.testing.expect(root.isRoot());
    try std.testing.expect(!alice.isRoot());
}
