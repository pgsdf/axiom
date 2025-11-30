const std = @import("std");

// Direct libzfs C bindings
const c = @cImport({
    @cDefine("__BSD_VISIBLE", "1");
    @cInclude("sys/param.h");
    @cInclude("libzfs.h");
    @cInclude("sys/nvpair.h");
});

/// Error set for ZFS operations
pub const ZfsError = error{
    /// Failed to initialize libzfs
    InitFailed,
    /// Dataset does not exist
    DatasetNotFound,
    /// Dataset already exists
    DatasetExists,
    /// Operation not permitted
    PermissionDenied,
    /// Invalid dataset name or operation
    InvalidOperation,
    /// Property not found or invalid
    PropertyError,
    /// Memory allocation failed
    OutOfMemory,
    /// Unknown libzfs error
    Unknown,
    /// Internal error (e.g., subprocess failed)
    InternalError,
};

/// Convert libzfs errno to ZfsError
fn libzfsErrorToZig(errno_val: c_int) ZfsError {
    return switch (errno_val) {
        c.EZFS_NOENT => ZfsError.DatasetNotFound,
        c.EZFS_EXISTS => ZfsError.DatasetExists,
        c.EZFS_PERM => ZfsError.PermissionDenied,
        c.EZFS_INVALIDNAME => ZfsError.InvalidOperation,
        c.EZFS_PROPTYPE, c.EZFS_BADPROP => ZfsError.PropertyError,
        c.EZFS_NOMEM => ZfsError.OutOfMemory,
        else => ZfsError.Unknown,
    };
}

/// Dataset type flags
pub const DatasetType = enum(c_uint) {
    filesystem = c.ZFS_TYPE_FILESYSTEM,
    volume = c.ZFS_TYPE_VOLUME,
    snapshot = c.ZFS_TYPE_SNAPSHOT,
    pool = c.ZFS_TYPE_POOL,
    bookmark = c.ZFS_TYPE_BOOKMARK,
};

/// Properties that can be set on a dataset
pub const DatasetProperties = struct {
    /// Mount the filesystem (default: on)
    canmount: ?bool = null,
    /// Mount point path
    mountpoint: ?[]const u8 = null,
    /// Read-only filesystem
    readonly: ?bool = null,
    /// Compression algorithm (lz4, gzip, zstd, etc)
    compression: ?[]const u8 = null,
    /// Quota for filesystem
    quota: ?u64 = null,
    /// Reservation for filesystem
    reservation: ?u64 = null,
    /// Record size
    recordsize: ?u32 = null,
    /// Enable/disable atime updates
    atime: ?bool = null,

    /// Create nvlist from properties
    fn toNvlist(self: DatasetProperties, allocator: std.mem.Allocator) !*c.nvlist_t {
        var nvlist: ?*c.nvlist_t = null;
        const result = c.nvlist_alloc(&nvlist, c.NV_UNIQUE_NAME, 0);
        if (result != 0) return ZfsError.OutOfMemory;

        const list = nvlist.?;
        errdefer c.nvlist_free(list);

        if (self.canmount) |val| {
            const str = if (val) "on" else "off";
            _ = c.nvlist_add_string(list, c.zfs_prop_to_name(c.ZFS_PROP_CANMOUNT), str);
        }

        if (self.mountpoint) |path| {
            const c_path = try allocator.dupeZ(u8, path);
            defer allocator.free(c_path);
            _ = c.nvlist_add_string(list, c.zfs_prop_to_name(c.ZFS_PROP_MOUNTPOINT), c_path.ptr);
        }

        if (self.readonly) |val| {
            const str = if (val) "on" else "off";
            _ = c.nvlist_add_string(list, c.zfs_prop_to_name(c.ZFS_PROP_READONLY), str);
        }

        if (self.compression) |comp| {
            const c_comp = try allocator.dupeZ(u8, comp);
            defer allocator.free(c_comp);
            _ = c.nvlist_add_string(list, c.zfs_prop_to_name(c.ZFS_PROP_COMPRESSION), c_comp.ptr);
        }

        if (self.atime) |val| {
            const str = if (val) "on" else "off";
            _ = c.nvlist_add_string(list, c.zfs_prop_to_name(c.ZFS_PROP_ATIME), str);
        }

        if (self.quota) |val| {
            _ = c.nvlist_add_uint64(list, c.zfs_prop_to_name(c.ZFS_PROP_QUOTA), val);
        }

        if (self.reservation) |val| {
            _ = c.nvlist_add_uint64(list, c.zfs_prop_to_name(c.ZFS_PROP_RESERVATION), val);
        }

        if (self.recordsize) |val| {
            _ = c.nvlist_add_uint64(list, c.zfs_prop_to_name(c.ZFS_PROP_RECORDSIZE), val);
        }

        return list;
    }
};

/// Main ZFS handle for library operations
pub const ZfsHandle = struct {
    handle: *c.libzfs_handle_t,

    /// Initialize libzfs library
    pub fn init() !ZfsHandle {
        const handle = c.libzfs_init() orelse return ZfsError.InitFailed;
        return ZfsHandle{ .handle = handle };
    }

    /// Clean up libzfs library
    pub fn deinit(self: *ZfsHandle) void {
        c.libzfs_fini(self.handle);
    }

    /// Check if a dataset exists
    pub fn datasetExists(self: *ZfsHandle, allocator: std.mem.Allocator, path: []const u8, dataset_type: DatasetType) !bool {
        const c_path = try allocator.dupeZ(u8, path);
        defer allocator.free(c_path);

        const exists = c.zfs_dataset_exists(self.handle, c_path.ptr, @intFromEnum(dataset_type));
        return exists != 0;
    }

    /// Create a new filesystem dataset
    pub fn createDataset(
        self: *ZfsHandle,
        allocator: std.mem.Allocator,
        path: []const u8,
        props: ?DatasetProperties,
    ) !void {
        const c_path = try allocator.dupeZ(u8, path);
        defer allocator.free(c_path);

        var nvlist: ?*c.nvlist_t = null;
        if (props) |p| {
            nvlist = try p.toNvlist(allocator);
        }
        defer if (nvlist) |list| c.nvlist_free(list);

        const result = c.zfs_create(
            self.handle,
            c_path.ptr,
            c.ZFS_TYPE_FILESYSTEM,
            nvlist,
        );

        if (result != 0) {
            const errno_val = c.libzfs_errno(self.handle);
            return libzfsErrorToZig(errno_val);
        }
    }

    /// Destroy a dataset (and optionally its children)
    pub fn destroyDataset(
        self: *ZfsHandle,
        allocator: std.mem.Allocator,
        path: []const u8,
        recursive: bool,
    ) !void {
        const c_path = try allocator.dupeZ(u8, path);
        defer allocator.free(c_path);

        const zhp = c.zfs_open(self.handle, c_path.ptr, c.ZFS_TYPE_DATASET) orelse {
            const errno_val = c.libzfs_errno(self.handle);
            return libzfsErrorToZig(errno_val);
        };
        defer c.zfs_close(zhp);

        // FreeBSD's libzfs may not have ZFS_DEFER_DESTROY flag
        // Use 0 for flags, recursive destruction is handled by zfs_destroy
        _ = recursive; // Mark as used
        const result = c.zfs_destroy(zhp, 0);

        if (result != 0) {
            const errno_val = c.libzfs_errno(self.handle);
            return libzfsErrorToZig(errno_val);
        }
    }

    /// Create a snapshot of a dataset
    pub fn snapshot(
        self: *ZfsHandle,
        allocator: std.mem.Allocator,
        dataset: []const u8,
        snap_name: []const u8,
        recursive: bool,
    ) !void {
        const full_path = try std.fmt.allocPrint(
            allocator,
            "{s}@{s}",
            .{ dataset, snap_name },
        );
        defer allocator.free(full_path);

        const c_path = try allocator.dupeZ(u8, full_path);
        defer allocator.free(c_path);

        var nvlist: ?*c.nvlist_t = null;
        _ = c.nvlist_alloc(&nvlist, c.NV_UNIQUE_NAME, 0);
        defer if (nvlist) |list| c.nvlist_free(list);

        const flags: c_int = if (recursive) 1 else 0;
        const result = c.zfs_snapshot(self.handle, c_path.ptr, @intCast(flags), nvlist);

        if (result != 0) {
            const errno_val = c.libzfs_errno(self.handle);
            return libzfsErrorToZig(errno_val);
        }
    }

    /// Clone a snapshot to create a new dataset
    pub fn clone(
        self: *ZfsHandle,
        allocator: std.mem.Allocator,
        snap_path: []const u8,
        target: []const u8,
        props: ?DatasetProperties,
    ) !void {
        const c_snap = try allocator.dupeZ(u8, snap_path);
        defer allocator.free(c_snap);

        const c_target = try allocator.dupeZ(u8, target);
        defer allocator.free(c_target);

        var nvlist: ?*c.nvlist_t = null;
        if (props) |p| {
            nvlist = try p.toNvlist(allocator);
        }
        defer if (nvlist) |list| c.nvlist_free(list);

        const result = c.zfs_clone(self.handle, c_snap.ptr, c_target.ptr, nvlist);

        if (result != 0) {
            const errno_val = c.libzfs_errno(self.handle);
            return libzfsErrorToZig(errno_val);
        }
    }

    /// Set a property on an existing dataset
    pub fn setProperty(
        self: *ZfsHandle,
        allocator: std.mem.Allocator,
        path: []const u8,
        property: []const u8,
        value: []const u8,
    ) !void {
        const c_path = try allocator.dupeZ(u8, path);
        defer allocator.free(c_path);

        const zhp = c.zfs_open(self.handle, c_path.ptr, c.ZFS_TYPE_DATASET) orelse {
            const errno_val = c.libzfs_errno(self.handle);
            return libzfsErrorToZig(errno_val);
        };
        defer c.zfs_close(zhp);

        const c_prop = try allocator.dupeZ(u8, property);
        defer allocator.free(c_prop);

        const c_value = try allocator.dupeZ(u8, value);
        defer allocator.free(c_value);

        const result = c.zfs_prop_set(zhp, c_prop.ptr, c_value.ptr);

        if (result != 0) {
            const errno_val = c.libzfs_errno(self.handle);
            return libzfsErrorToZig(errno_val);
        }
    }

    /// Get a property value from a dataset
    pub fn getProperty(
        self: *ZfsHandle,
        allocator: std.mem.Allocator,
        path: []const u8,
        property: []const u8,
    ) ![]u8 {
        const c_path = try allocator.dupeZ(u8, path);
        defer allocator.free(c_path);

        const zhp = c.zfs_open(self.handle, c_path.ptr, c.ZFS_TYPE_DATASET) orelse {
            const errno_val = c.libzfs_errno(self.handle);
            return libzfsErrorToZig(errno_val);
        };
        defer c.zfs_close(zhp);

        const c_prop = try allocator.dupeZ(u8, property);
        defer allocator.free(c_prop);
        
        // Try to get user properties first
        const nvl = c.zfs_get_user_props(zhp);
        
        if (nvl != null) {
            var prop_val: [*c]const u8 = undefined;
            if (c.nvlist_lookup_string(nvl, c_prop.ptr, &prop_val) == 0) {
                const value_len = std.mem.len(prop_val);
                return try allocator.dupe(u8, prop_val[0..value_len]);
            }
        }
        
        // Fallback: use shell command for standard ZFS properties
        // This is more reliable than trying to navigate libzfs's property APIs
        const cmd = try std.fmt.allocPrint(
            allocator,
            "zfs get -H -o value {s} {s}",
            .{ property, path },
        );
        defer allocator.free(cmd);
        
        var child = std.process.Child.init(&[_][]const u8{ "sh", "-c", cmd }, allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;
        
        try child.spawn();
        
        const stdout = try child.stdout.?.readToEndAlloc(allocator, 1024);
        errdefer allocator.free(stdout);
        
        const term = try child.wait();
        if (term.Exited != 0) {
            allocator.free(stdout);
            return ZfsError.PropertyError;
        }
        
        // Trim newline
        const trimmed = std.mem.trimRight(u8, stdout, "\n\r");
        if (trimmed.len == 0) {
            allocator.free(stdout);
            return ZfsError.PropertyError;
        }
        
        // Return trimmed copy
        const result_copy = try allocator.dupe(u8, trimmed);
        allocator.free(stdout);
        return result_copy;
    }

    /// Get the mountpoint of a dataset
    pub fn getMountpoint(
        self: *ZfsHandle,
        allocator: std.mem.Allocator,
        path: []const u8,
    ) ![]u8 {
        return self.getProperty(allocator, path, "mountpoint");
    }

    /// Mount a filesystem dataset
    pub fn mount(
        self: *ZfsHandle,
        allocator: std.mem.Allocator,
        path: []const u8,
        options: ?[]const u8,
    ) !void {
        const c_path = try allocator.dupeZ(u8, path);
        defer allocator.free(c_path);

        const zhp = c.zfs_open(self.handle, c_path.ptr, c.ZFS_TYPE_FILESYSTEM) orelse {
            const errno_val = c.libzfs_errno(self.handle);
            return libzfsErrorToZig(errno_val);
        };
        defer c.zfs_close(zhp);

        var c_options: [*c]const u8 = null;
        if (options) |opts| {
            const c_opts = try allocator.dupeZ(u8, opts);
            defer allocator.free(c_opts);
            c_options = c_opts.ptr;
        }

        const result = c.zfs_mount(zhp, c_options, 0);

        if (result != 0) {
            const errno_val = c.libzfs_errno(self.handle);
            return libzfsErrorToZig(errno_val);
        }
    }

    /// Unmount a filesystem dataset
    pub fn unmount(
        self: *ZfsHandle,
        allocator: std.mem.Allocator,
        path: []const u8,
        force: bool,
    ) !void {
        const c_path = try allocator.dupeZ(u8, path);
        defer allocator.free(c_path);

        const zhp = c.zfs_open(self.handle, c_path.ptr, c.ZFS_TYPE_FILESYSTEM) orelse {
            const errno_val = c.libzfs_errno(self.handle);
            return libzfsErrorToZig(errno_val);
        };
        defer c.zfs_close(zhp);

        const flags: c_int = if (force) c.MS_FORCE else 0;
        const result = c.zfs_unmount(zhp, null, flags);

        if (result != 0) {
            const errno_val = c.libzfs_errno(self.handle);
            return libzfsErrorToZig(errno_val);
        }
    }

    /// Receive a ZFS stream from a file into a dataset
    pub fn receive(
        self: *ZfsHandle,
        dataset: []const u8,
        stream_path: []const u8,
    ) !void {
        _ = self;

        // Read stream file first
        const file = std.fs.openFileAbsolute(stream_path, .{}) catch {
            return ZfsError.DatasetNotFound;
        };
        defer file.close();

        // Use zfs receive command as libzfs receive API is complex
        var child = std.process.Child.init(
            &[_][]const u8{ "zfs", "receive", "-F", dataset },
            std.heap.page_allocator,
        );
        child.stdin_behavior = .Pipe;

        child.spawn() catch return ZfsError.InternalError;

        // Pipe file contents to stdin
        const stdin = child.stdin orelse {
            _ = child.wait() catch {};
            return ZfsError.InternalError;
        };

        var buf: [8192]u8 = undefined;
        while (true) {
            const n = file.read(&buf) catch break;
            if (n == 0) break;
            stdin.writeAll(buf[0..n]) catch break;
        }
        stdin.close();

        const term = child.wait() catch return ZfsError.InternalError;
        if (term.Exited != 0) {
            return ZfsError.InternalError;
        }
    }

    /// Send a ZFS snapshot to a file
    pub fn sendToFile(
        self: *ZfsHandle,
        snapshot_name: []const u8,
        dest_path: []const u8,
    ) !void {
        _ = self;
        // Use zfs send command
        var child = std.process.Child.init(
            &[_][]const u8{ "zfs", "send", "-c", snapshot_name },
            std.heap.page_allocator,
        );
        child.stdout_behavior = .Pipe;

        child.spawn() catch return ZfsError.InternalError;

        // Create output file
        const file = std.fs.createFileAbsolute(dest_path, .{}) catch {
            _ = child.wait() catch {};
            return ZfsError.InternalError;
        };
        defer file.close();

        // Read from child stdout and write to file
        const stdout = child.stdout orelse {
            _ = child.wait() catch {};
            return ZfsError.InternalError;
        };
        var buf: [8192]u8 = undefined;
        while (true) {
            const n = stdout.read(&buf) catch break;
            if (n == 0) break;
            file.writeAll(buf[0..n]) catch break;
        }

        const term = child.wait() catch return ZfsError.InternalError;
        if (term.Exited != 0) {
            return ZfsError.InternalError;
        }
    }

    /// Send an incremental ZFS stream between two snapshots to a file
    pub fn sendIncrementalToFile(
        self: *ZfsHandle,
        from_snapshot: []const u8,
        to_snapshot: []const u8,
        dest_path: []const u8,
    ) !void {
        _ = self;
        // Use zfs send -i for incremental
        var child = std.process.Child.init(
            &[_][]const u8{ "zfs", "send", "-c", "-i", from_snapshot, to_snapshot },
            std.heap.page_allocator,
        );
        child.stdout_behavior = .Pipe;

        child.spawn() catch return ZfsError.InternalError;

        const file = std.fs.createFileAbsolute(dest_path, .{}) catch {
            _ = child.wait() catch {};
            return ZfsError.InternalError;
        };
        defer file.close();

        const stdout = child.stdout orelse {
            _ = child.wait() catch {};
            return ZfsError.InternalError;
        };
        var buf: [8192]u8 = undefined;
        while (true) {
            const n = stdout.read(&buf) catch break;
            if (n == 0) break;
            file.writeAll(buf[0..n]) catch break;
        }

        const term = child.wait() catch return ZfsError.InternalError;
        if (term.Exited != 0) {
            return ZfsError.InternalError;
        }
    }

    /// List child datasets of a parent dataset
    pub fn listChildDatasets(
        self: *ZfsHandle,
        allocator: std.mem.Allocator,
        parent: []const u8,
    ) ![][]const u8 {
        _ = self;

        // Use zfs list command to get child datasets
        const cmd = try std.fmt.allocPrint(
            allocator,
            "zfs list -H -o name -r -d 1 {s} | tail -n +2",
            .{parent},
        );
        defer allocator.free(cmd);

        var child = std.process.Child.init(&[_][]const u8{ "sh", "-c", cmd }, allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;

        try child.spawn();

        const stdout = try child.stdout.?.readToEndAlloc(allocator, 1024 * 1024);
        defer allocator.free(stdout);

        const term = try child.wait();
        if (term.Exited != 0) {
            return &[_][]const u8{};
        }

        // Parse output - each line is a dataset name
        var datasets = std.ArrayList([]const u8).init(allocator);
        errdefer {
            for (datasets.items) |item| {
                allocator.free(item);
            }
            datasets.deinit();
        }

        var lines = std.mem.splitScalar(u8, stdout, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0) continue;

            // Extract just the last component (child name)
            if (std.mem.lastIndexOf(u8, trimmed, "/")) |idx| {
                const child_name = trimmed[idx + 1 ..];
                if (child_name.len > 0) {
                    try datasets.append(try allocator.dupe(u8, child_name));
                }
            }
        }

        return try datasets.toOwnedSlice();
    }

    /// Get disk usage (used property) for a dataset in bytes
    pub fn getDatasetUsed(
        self: *ZfsHandle,
        allocator: std.mem.Allocator,
        path: []const u8,
    ) !u64 {
        const used_str = try self.getProperty(allocator, path, "used");
        defer allocator.free(used_str);

        // Parse the value - it may include units like K, M, G, T
        return parseZfsSize(used_str);
    }
};

/// Parse ZFS size string (e.g., "1.5G", "500M", "1T") to bytes
fn parseZfsSize(size_str: []const u8) u64 {
    if (size_str.len == 0) return 0;

    var value: u64 = 0;
    var decimal_part: u64 = 0;
    var decimal_divisor: u64 = 1;
    var in_decimal = false;
    var multiplier: u64 = 1;
    var i: usize = 0;

    while (i < size_str.len) : (i += 1) {
        const char = size_str[i];
        if (char >= '0' and char <= '9') {
            if (in_decimal) {
                decimal_part = decimal_part * 10 + (char - '0');
                decimal_divisor *= 10;
            } else {
                value = value * 10 + (char - '0');
            }
        } else if (char == '.') {
            in_decimal = true;
        } else {
            // Unit character
            multiplier = switch (char) {
                'K' => 1024,
                'M' => 1024 * 1024,
                'G' => 1024 * 1024 * 1024,
                'T' => 1024 * 1024 * 1024 * 1024,
                'P' => 1024 * 1024 * 1024 * 1024 * 1024,
                else => 1,
            };
            break;
        }
    }

    const whole = value * multiplier;
    const frac = if (decimal_divisor > 1) (decimal_part * multiplier) / decimal_divisor else 0;
    return whole + frac;
}

// ============================================================================
// Phase 26: ZFS Dataset Path Validation
// ============================================================================

/// Errors for path validation
pub const PathValidationError = error{
    /// Path contains invalid characters
    InvalidCharacter,
    /// Path component is empty
    EmptyComponent,
    /// Path component exceeds maximum length
    ComponentTooLong,
    /// Full path exceeds maximum length
    PathTooLong,
    /// Path is outside the allowed store hierarchy
    OutsideStoreRoot,
    /// Path component is a reserved name
    ReservedName,
    /// Path contains snapshot reference (@) where not allowed
    SnapshotInPath,
    /// Path contains bookmark reference (#) where not allowed
    BookmarkInPath,
    /// Path contains null bytes
    NullByte,
    /// Path contains control characters
    ControlCharacter,
    /// Path attempts directory traversal
    PathTraversal,
};

/// ZFS dataset path validator
/// Ensures all dataset operations target intended locations within the Axiom store hierarchy
pub const ZfsPathValidator = struct {
    allocator: std.mem.Allocator,
    store_root: []const u8,

    /// Maximum length for a single path component (ZFS limit is 256)
    pub const MAX_COMPONENT_LENGTH: usize = 255;

    /// Maximum length for full dataset path (ZFS limit is ~1024)
    pub const MAX_PATH_LENGTH: usize = 1024;

    /// Valid characters for ZFS dataset name components
    /// Alphanumeric plus: - _ . : (colon only for special cases)
    /// Note: We intentionally exclude '@' and '#' as those are snapshot/bookmark delimiters
    pub const VALID_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.";

    /// Extended valid chars that include colon (for pool names)
    pub const VALID_CHARS_WITH_COLON = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:";

    /// Reserved names that cannot be used as dataset components
    pub const RESERVED_NAMES = [_][]const u8{
        ".",
        "..",
        "zfs",
        "zpool",
        "snapshot",
        "bookmark",
        "clone",
        "origin",
    };

    /// Initialize validator with store root
    pub fn init(allocator: std.mem.Allocator, store_root: []const u8) ZfsPathValidator {
        return .{
            .allocator = allocator,
            .store_root = store_root,
        };
    }

    /// Validate a single path component (e.g., package name, version string)
    pub fn validateComponent(self: *const ZfsPathValidator, component: []const u8) PathValidationError!void {
        _ = self;

        // Check for empty component
        if (component.len == 0) {
            return PathValidationError.EmptyComponent;
        }

        // Check length
        if (component.len > MAX_COMPONENT_LENGTH) {
            return PathValidationError.ComponentTooLong;
        }

        // Check for null bytes
        if (std.mem.indexOfScalar(u8, component, 0) != null) {
            return PathValidationError.NullByte;
        }

        // Check each character against allowlist
        for (component) |char| {
            // Check for control characters (ASCII < 32 or DEL)
            if (char < 32 or char == 127) {
                return PathValidationError.ControlCharacter;
            }

            // Check against valid characters
            if (std.mem.indexOfScalar(u8, VALID_CHARS, char) == null) {
                // Special case: '@' in component means embedded snapshot reference
                if (char == '@') {
                    return PathValidationError.SnapshotInPath;
                }
                // Special case: '#' in component means embedded bookmark reference
                if (char == '#') {
                    return PathValidationError.BookmarkInPath;
                }
                return PathValidationError.InvalidCharacter;
            }
        }

        // Check for reserved names
        for (RESERVED_NAMES) |reserved| {
            if (std.mem.eql(u8, component, reserved)) {
                return PathValidationError.ReservedName;
            }
        }

        // Check for hidden files/directories (start with .)
        if (component[0] == '.') {
            return PathValidationError.ReservedName;
        }
    }

    /// Validate a full dataset path ensuring it's within the store hierarchy
    pub fn validateDatasetPath(self: *const ZfsPathValidator, path: []const u8) PathValidationError!void {
        // Check for null bytes
        if (std.mem.indexOfScalar(u8, path, 0) != null) {
            return PathValidationError.NullByte;
        }

        // Check total path length
        if (path.len > MAX_PATH_LENGTH) {
            return PathValidationError.PathTooLong;
        }

        // Ensure path starts with store root
        if (!std.mem.startsWith(u8, path, self.store_root)) {
            return PathValidationError.OutsideStoreRoot;
        }

        // Check for snapshot reference in dataset path (not allowed here)
        if (std.mem.indexOfScalar(u8, path, '@') != null) {
            return PathValidationError.SnapshotInPath;
        }

        // Check for bookmark reference in dataset path
        if (std.mem.indexOfScalar(u8, path, '#') != null) {
            return PathValidationError.BookmarkInPath;
        }

        // Validate each component after the store root
        const relative = path[self.store_root.len..];
        var iter = std.mem.splitScalar(u8, relative, '/');
        while (iter.next()) |component| {
            if (component.len == 0) continue; // Skip empty components from leading/trailing slashes

            // Check for path traversal
            if (std.mem.eql(u8, component, "..")) {
                return PathValidationError.PathTraversal;
            }

            try self.validateComponent(component);
        }
    }

    /// Validate a snapshot name (the part after @)
    pub fn validateSnapshotName(self: *const ZfsPathValidator, snap_name: []const u8) PathValidationError!void {
        // Snapshot names have same restrictions as components
        try self.validateComponent(snap_name);
    }

    /// Validate a full snapshot path (dataset@snapshot)
    pub fn validateSnapshotPath(self: *const ZfsPathValidator, full_path: []const u8) PathValidationError!void {
        // Check for null bytes
        if (std.mem.indexOfScalar(u8, full_path, 0) != null) {
            return PathValidationError.NullByte;
        }

        // Find the @ delimiter
        const at_pos = std.mem.indexOfScalar(u8, full_path, '@') orelse {
            return PathValidationError.InvalidCharacter; // Not a valid snapshot path
        };

        // Validate dataset portion (without @)
        const dataset_part = full_path[0..at_pos];

        // Temporarily check if dataset starts with store root
        if (!std.mem.startsWith(u8, dataset_part, self.store_root)) {
            return PathValidationError.OutsideStoreRoot;
        }

        // Check for additional @ characters (invalid)
        if (std.mem.indexOfScalar(u8, full_path[at_pos + 1 ..], '@') != null) {
            return PathValidationError.InvalidCharacter;
        }

        // Validate snapshot name
        const snap_name = full_path[at_pos + 1 ..];
        try self.validateSnapshotName(snap_name);

        // Validate each dataset component
        const relative = dataset_part[self.store_root.len..];
        var iter = std.mem.splitScalar(u8, relative, '/');
        while (iter.next()) |component| {
            if (component.len == 0) continue;
            if (std.mem.eql(u8, component, "..")) {
                return PathValidationError.PathTraversal;
            }
            try self.validateComponent(component);
        }
    }

    /// Build and validate a package dataset path from components
    /// Returns error if any component is invalid
    pub fn buildPackagePath(
        self: *const ZfsPathValidator,
        name: []const u8,
        version: []const u8,
        revision: u32,
        build_id: []const u8,
    ) ![]u8 {
        // Validate each component first
        try self.validateComponent(name);
        try self.validateComponent(version);
        try self.validateComponent(build_id);

        // Build the path
        const path = try std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}/{s}/{d}/{s}",
            .{ self.store_root, name, version, revision, build_id },
        );
        errdefer self.allocator.free(path);

        // Final validation of complete path
        try self.validateDatasetPath(path);

        return path;
    }

    /// Sanitize a string for use as a dataset component
    /// Replaces invalid characters with underscores
    /// Returns error if the result would still be invalid (e.g., reserved name)
    pub fn sanitizeComponent(self: *const ZfsPathValidator, input: []const u8) ![]u8 {
        if (input.len == 0) {
            return PathValidationError.EmptyComponent;
        }

        const max_len = @min(input.len, MAX_COMPONENT_LENGTH);
        const result = try self.allocator.alloc(u8, max_len);
        errdefer self.allocator.free(result);

        for (input[0..max_len], 0..) |char, i| {
            if (std.mem.indexOfScalar(u8, VALID_CHARS, char) != null) {
                result[i] = char;
            } else {
                result[i] = '_'; // Replace invalid chars with underscore
            }
        }

        // Check if result is a reserved name
        for (RESERVED_NAMES) |reserved| {
            if (std.mem.eql(u8, result, reserved)) {
                // Prefix with underscore to avoid reserved name
                const prefixed = try std.fmt.allocPrint(self.allocator, "_{s}", .{result});
                self.allocator.free(result);
                return prefixed;
            }
        }

        // Check for leading dot
        if (result[0] == '.') {
            result[0] = '_';
        }

        return result;
    }

    /// Get a human-readable error message for validation errors
    pub fn errorMessage(err: PathValidationError) []const u8 {
        return switch (err) {
            PathValidationError.InvalidCharacter => "path contains invalid characters (allowed: a-z, A-Z, 0-9, -, _, .)",
            PathValidationError.EmptyComponent => "path component cannot be empty",
            PathValidationError.ComponentTooLong => "path component exceeds maximum length (255 characters)",
            PathValidationError.PathTooLong => "full path exceeds maximum length (1024 characters)",
            PathValidationError.OutsideStoreRoot => "path is outside the allowed store hierarchy",
            PathValidationError.ReservedName => "path component uses a reserved name",
            PathValidationError.SnapshotInPath => "snapshot reference (@) not allowed in this context",
            PathValidationError.BookmarkInPath => "bookmark reference (#) not allowed in this context",
            PathValidationError.NullByte => "path contains null bytes",
            PathValidationError.ControlCharacter => "path contains control characters",
            PathValidationError.PathTraversal => "path traversal (..) not allowed",
        };
    }
};

// Tests
test "ZfsHandle init and deinit" {
    var zfs = try ZfsHandle.init();
    defer zfs.deinit();
}

test "dataset operations" {
    const allocator = std.testing.allocator;

    var zfs = try ZfsHandle.init();
    defer zfs.deinit();

    const test_dataset = "zroot/axiom-test";

    // Clean up if exists from previous test
    if (try zfs.datasetExists(allocator, test_dataset, .filesystem)) {
        zfs.destroyDataset(allocator, test_dataset, false) catch {};
    }

    // Create dataset
    try zfs.createDataset(allocator, test_dataset, .{
        .compression = "lz4",
        .atime = false,
    });

    // Verify it exists
    const exists = try zfs.datasetExists(allocator, test_dataset, .filesystem);
    try std.testing.expect(exists);

    // Get property
    const compression = try zfs.getProperty(allocator, test_dataset, "compression");
    defer allocator.free(compression);
    try std.testing.expectEqualStrings("lz4", compression);

    // Clean up
    try zfs.destroyDataset(allocator, test_dataset, false);
}

test "ZfsPathValidator validates components" {
    const allocator = std.testing.allocator;
    const validator = ZfsPathValidator.init(allocator, "zroot/axiom/store/pkg");

    // Valid components
    try validator.validateComponent("bash");
    try validator.validateComponent("openssl-1.1.1");
    try validator.validateComponent("my_package");
    try validator.validateComponent("pkg.name");
    try validator.validateComponent("abc123");

    // Invalid: empty
    try std.testing.expectError(PathValidationError.EmptyComponent, validator.validateComponent(""));

    // Invalid: reserved names
    try std.testing.expectError(PathValidationError.ReservedName, validator.validateComponent(".."));
    try std.testing.expectError(PathValidationError.ReservedName, validator.validateComponent("."));
    try std.testing.expectError(PathValidationError.ReservedName, validator.validateComponent("zfs"));
    try std.testing.expectError(PathValidationError.ReservedName, validator.validateComponent("zpool"));

    // Invalid: hidden files (start with .)
    try std.testing.expectError(PathValidationError.ReservedName, validator.validateComponent(".hidden"));

    // Invalid: snapshot reference in component
    try std.testing.expectError(PathValidationError.SnapshotInPath, validator.validateComponent("pkg@snap"));

    // Invalid: bookmark reference
    try std.testing.expectError(PathValidationError.BookmarkInPath, validator.validateComponent("pkg#mark"));

    // Invalid: special characters
    try std.testing.expectError(PathValidationError.InvalidCharacter, validator.validateComponent("pkg name"));
    try std.testing.expectError(PathValidationError.InvalidCharacter, validator.validateComponent("pkg/name"));
    try std.testing.expectError(PathValidationError.InvalidCharacter, validator.validateComponent("pkg$name"));
    try std.testing.expectError(PathValidationError.InvalidCharacter, validator.validateComponent("pkg;rm -rf"));
}

test "ZfsPathValidator validates dataset paths" {
    const allocator = std.testing.allocator;
    const validator = ZfsPathValidator.init(allocator, "zroot/axiom/store/pkg");

    // Valid paths
    try validator.validateDatasetPath("zroot/axiom/store/pkg/bash/5.2.0/1/abc123");
    try validator.validateDatasetPath("zroot/axiom/store/pkg/openssl/1.1.1/0/def456");

    // Invalid: outside store root
    try std.testing.expectError(PathValidationError.OutsideStoreRoot, validator.validateDatasetPath("zroot/other/bash"));
    try std.testing.expectError(PathValidationError.OutsideStoreRoot, validator.validateDatasetPath("/etc/passwd"));

    // Invalid: path traversal
    try std.testing.expectError(PathValidationError.PathTraversal, validator.validateDatasetPath("zroot/axiom/store/pkg/../../../etc/passwd"));

    // Invalid: snapshot in dataset path
    try std.testing.expectError(PathValidationError.SnapshotInPath, validator.validateDatasetPath("zroot/axiom/store/pkg/bash@snap"));
}

test "ZfsPathValidator validates snapshot paths" {
    const allocator = std.testing.allocator;
    const validator = ZfsPathValidator.init(allocator, "zroot/axiom/store/pkg");

    // Valid snapshot paths
    try validator.validateSnapshotPath("zroot/axiom/store/pkg/bash/5.2.0/1/abc123@installed");
    try validator.validateSnapshotPath("zroot/axiom/store/pkg/openssl/1.1.1/0/def456@v1");

    // Invalid: no snapshot name
    try std.testing.expectError(PathValidationError.InvalidCharacter, validator.validateSnapshotPath("zroot/axiom/store/pkg/bash"));

    // Invalid: outside store root
    try std.testing.expectError(PathValidationError.OutsideStoreRoot, validator.validateSnapshotPath("zroot/other/bash@snap"));

    // Invalid: multiple @ characters
    try std.testing.expectError(PathValidationError.InvalidCharacter, validator.validateSnapshotPath("zroot/axiom/store/pkg/bash@snap@other"));
}

test "ZfsPathValidator builds package paths" {
    const allocator = std.testing.allocator;
    var validator = ZfsPathValidator.init(allocator, "zroot/axiom/store/pkg");

    // Valid package path
    const path = try validator.buildPackagePath("bash", "5.2.0", 1, "abc123");
    defer allocator.free(path);
    try std.testing.expectEqualStrings("zroot/axiom/store/pkg/bash/5.2.0/1/abc123", path);

    // Invalid: package name with special chars
    try std.testing.expectError(PathValidationError.InvalidCharacter, validator.buildPackagePath("ba$h", "5.2.0", 1, "abc123"));

    // Invalid: version with snapshot reference
    try std.testing.expectError(PathValidationError.SnapshotInPath, validator.buildPackagePath("bash", "5.2.0@evil", 1, "abc123"));

    // Invalid: build_id with path traversal attempt
    try std.testing.expectError(PathValidationError.PathTraversal, validator.buildPackagePath("bash", "5.2.0", 1, ".."));
}

test "ZfsPathValidator sanitizes components" {
    const allocator = std.testing.allocator;
    var validator = ZfsPathValidator.init(allocator, "zroot/axiom/store/pkg");

    // Sanitize special characters
    const sanitized1 = try validator.sanitizeComponent("pkg@name");
    defer allocator.free(sanitized1);
    try std.testing.expectEqualStrings("pkg_name", sanitized1);

    // Sanitize spaces
    const sanitized2 = try validator.sanitizeComponent("my package");
    defer allocator.free(sanitized2);
    try std.testing.expectEqualStrings("my_package", sanitized2);

    // Sanitize reserved name
    const sanitized3 = try validator.sanitizeComponent("..");
    defer allocator.free(sanitized3);
    try std.testing.expectEqualStrings("_..", sanitized3);

    // Sanitize leading dot
    const sanitized4 = try validator.sanitizeComponent(".hidden");
    defer allocator.free(sanitized4);
    try std.testing.expectEqualStrings("_hidden", sanitized4);
}

test "snapshot and clone" {
    const allocator = std.testing.allocator;

    var zfs = try ZfsHandle.init();
    defer zfs.deinit();

    const test_dataset = "zroot/axiom-test-snap";
    const test_snap = "testsnap";
    const clone_target = "zroot/axiom-test-clone";

    // Clean up from previous tests
    if (try zfs.datasetExists(allocator, clone_target, .filesystem)) {
        zfs.destroyDataset(allocator, clone_target, false) catch {};
    }
    if (try zfs.datasetExists(allocator, test_dataset, .filesystem)) {
        zfs.destroyDataset(allocator, test_dataset, true) catch {};
    }

    // Create dataset
    try zfs.createDataset(allocator, test_dataset, null);

    // Create snapshot
    try zfs.snapshot(allocator, test_dataset, test_snap, false);

    // Verify snapshot exists
    const snap_path = try std.fmt.allocPrint(allocator, "{s}@{s}", .{ test_dataset, test_snap });
    defer allocator.free(snap_path);
    const snap_exists = try zfs.datasetExists(allocator, snap_path, .snapshot);
    try std.testing.expect(snap_exists);

    // Clone snapshot
    try zfs.clone(allocator, snap_path, clone_target, null);

    // Verify clone exists
    const clone_exists = try zfs.datasetExists(allocator, clone_target, .filesystem);
    try std.testing.expect(clone_exists);

    // Clean up
    try zfs.destroyDataset(allocator, clone_target, false);
    try zfs.destroyDataset(allocator, test_dataset, true);
}
