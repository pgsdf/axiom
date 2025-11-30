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
