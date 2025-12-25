const std = @import("std");
const errors = @import("errors.zig");

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
    /// Dataset is busy (mounted, has dependents, etc.)
    DatasetBusy,
    /// Unknown libzfs error
    Unknown,
    /// Internal error (e.g., subprocess failed)
    InternalError,
    /// Invalid dataset name (contains shell metacharacters or invalid characters)
    InvalidDatasetName,
    /// Invalid property name
    InvalidPropertyName,
};

// ============================================================================
// Phase 51: Shell Command Injection Prevention
// ============================================================================

/// Validate that a string is safe to use as a ZFS dataset name
/// Prevents shell command injection by rejecting shell metacharacters
/// Only allows: alphanumeric, underscore, hyphen, slash, colon, period, @, #
pub fn isValidDatasetName(name: []const u8) bool {
    if (name.len == 0) return false;

    for (name) |ch| {
        const valid = switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9' => true,
            '_', '-', '/', ':', '.', '@', '#' => true,
            else => false,
        };
        if (!valid) return false;
    }

    // Additional checks for dangerous patterns
    // Reject if contains shell metacharacters that could escape validation
    if (std.mem.indexOf(u8, name, "$(") != null) return false;
    if (std.mem.indexOf(u8, name, "`") != null) return false;
    if (std.mem.indexOf(u8, name, ";") != null) return false;
    if (std.mem.indexOf(u8, name, "&") != null) return false;
    if (std.mem.indexOf(u8, name, "|") != null) return false;
    if (std.mem.indexOf(u8, name, ">") != null) return false;
    if (std.mem.indexOf(u8, name, "<") != null) return false;
    if (std.mem.indexOf(u8, name, "\n") != null) return false;
    if (std.mem.indexOf(u8, name, "\r") != null) return false;
    if (std.mem.indexOf(u8, name, "'") != null) return false;
    if (std.mem.indexOf(u8, name, "\"") != null) return false;
    if (std.mem.indexOfScalar(u8, name, 0) != null) return false; // NUL byte

    return true;
}

/// Validate that a string is safe to use as a ZFS property name
/// More restrictive than dataset names - only alphanumeric, underscore, colon
pub fn isValidPropertyName(name: []const u8) bool {
    if (name.len == 0) return false;

    for (name) |ch| {
        const valid = switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9' => true,
            '_', ':', '.' => true,
            else => false,
        };
        if (!valid) return false;
    }

    return true;
}

/// Convert libzfs errno to ZfsError
fn libzfsErrorToZig(errno_val: c_int) ZfsError {
    return switch (errno_val) {
        c.EZFS_NOENT => ZfsError.DatasetNotFound,
        c.EZFS_EXISTS => ZfsError.DatasetExists,
        c.EZFS_PERM => ZfsError.PermissionDenied,
        c.EZFS_INVALIDNAME => ZfsError.InvalidOperation,
        c.EZFS_PROPTYPE, c.EZFS_BADPROP => ZfsError.PropertyError,
        c.EZFS_NOMEM => ZfsError.OutOfMemory,
        c.EZFS_BUSY => ZfsError.DatasetBusy,
        else => {
            std.debug.print("Unknown ZFS error code: {d}\n", .{errno_val});
            return ZfsError.Unknown;
        },
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
/// Thread-safe wrapper around libzfs_handle_t using mutex synchronization
///
/// ## Thread Safety
///
/// All public methods are thread-safe through internal mutex protection.
/// The mutex is automatically acquired and released by each operation.
///
/// ### Operations requiring mutex (mutating):
/// - `createDataset()` - Creates new ZFS filesystem
/// - `createDatasetWithParents()` - Creates dataset with parent creation
/// - `destroyDataset()` - Destroys a dataset
/// - `createSnapshot()` - Creates a snapshot
/// - `cloneSnapshot()` - Clones a snapshot to new dataset
/// - `setProperty()` - Sets a dataset property
/// - `mount()` - Mounts a filesystem
/// - `unmount()` - Unmounts a filesystem
/// - `deinit()` - Cleans up the handle
///
/// ### Operations requiring mutex (read-only but libzfs not thread-safe):
/// - `datasetExists()` - Checks if dataset exists
/// - `getProperty()` - Gets a dataset property
/// - `listDatasets()` - Lists child datasets
///
/// ### Thread-safe patterns:
/// - Multiple ZfsHandle instances CAN operate concurrently (separate libzfs handles)
/// - Single ZfsHandle instance operations are serialized via mutex
/// - Prefer `withLock()` for custom compound operations
///
/// ### Lock ordering (to prevent deadlocks):
/// - ZfsHandle.mutex must be acquired BEFORE any other application locks
/// - Never call external code while holding ZfsHandle.mutex
/// - Never acquire ZfsHandle.mutex while holding GarbageCollector lock
///
pub const ZfsHandle = struct {
    handle: *c.libzfs_handle_t,
    /// Mutex to protect libzfs operations which are not thread-safe.
    /// All public methods acquire this mutex internally.
    mutex: std.Thread.Mutex = .{},

    /// Initialize libzfs library
    pub fn init() !ZfsHandle {
        const handle = c.libzfs_init() orelse return ZfsError.InitFailed;
        return ZfsHandle{ .handle = handle };
    }

    /// Clean up libzfs library
    pub fn deinit(self: *ZfsHandle) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        c.libzfs_fini(self.handle);
    }

    /// Execute a compound operation with the mutex held.
    /// Use this for operations that need to perform multiple ZFS calls atomically.
    ///
    /// Example:
    /// ```zig
    /// const result = try zfs.withLock(struct {
    ///     pub fn call(handle: *c.libzfs_handle_t) !void {
    ///         // Multiple libzfs calls here are atomic
    ///     }
    /// }.call);
    /// ```
    ///
    /// WARNING: Do not call other ZfsHandle methods from within the callback,
    /// as they will attempt to acquire the mutex and deadlock.
    pub fn withLock(self: *ZfsHandle, comptime callback: fn (*c.libzfs_handle_t) anyerror!void) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        return callback(self.handle);
    }

    /// Get the raw libzfs handle for advanced operations.
    /// CALLER MUST hold the mutex via withLock() or manually.
    /// This is unsafe and should only be used when withLock() is insufficient.
    pub fn getRawHandle(self: *ZfsHandle) *c.libzfs_handle_t {
        return self.handle;
    }

    /// Check if a dataset exists
    pub fn datasetExists(self: *ZfsHandle, allocator: std.mem.Allocator, path: []const u8, dataset_type: DatasetType) !bool {
        const c_path = try allocator.dupeZ(u8, path);
        defer allocator.free(c_path);

        self.mutex.lock();
        defer self.mutex.unlock();

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

        self.mutex.lock();
        defer self.mutex.unlock();

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

    /// Create a new filesystem dataset with parent creation (like zfs create -p)
    /// SECURITY: Uses direct execve instead of shell to prevent command injection
    pub fn createDatasetWithParents(
        self: *ZfsHandle,
        allocator: std.mem.Allocator,
        path: []const u8,
        props: ?DatasetProperties,
    ) !void {
        _ = self; // Accessed via subprocess

        // SECURITY: Validate dataset name to prevent command injection
        if (!isValidDatasetName(path)) {
            return ZfsError.InvalidDatasetName;
        }

        // Build argument list for direct execve (no shell)
        var args: std.ArrayList([]const u8) = .empty;
        defer args.deinit(allocator);

        // Track allocated strings that need to be freed after execution
        var allocated_args: std.ArrayList([]const u8) = .empty;
        defer {
            for (allocated_args.items) |s| allocator.free(s);
            allocated_args.deinit(allocator);
        }

        try args.append(allocator, "zfs");
        try args.append(allocator, "create");
        try args.append(allocator, "-p");

        // Add properties if provided (validated)
        if (props) |p| {
            if (p.compression) |comp| {
                // Validate property value
                if (!isValidPropertyName(comp)) {
                    return ZfsError.InvalidPropertyName;
                }
                const comp_opt = try std.fmt.allocPrint(allocator, "compression={s}", .{comp});
                try allocated_args.append(allocator, comp_opt);
                try args.append(allocator, "-o");
                try args.append(allocator, comp_opt);
            }
            if (p.atime != null and !p.atime.?) {
                try args.append(allocator, "-o");
                try args.append(allocator, "atime=off");
            }
        }

        try args.append(allocator, path);

        // Use direct execve - no shell involved
        var child = std.process.Child.init(args.items, allocator);
        child.stderr_behavior = .Pipe;
        child.stdout_behavior = .Ignore;
        try child.spawn();

        var stderr_output: ?[]const u8 = null;
        if (child.stderr) |stderr_pipe| {
            stderr_output = stderr_pipe.readToEndAlloc(allocator, 1024 * 1024) catch null;
        }
        defer if (stderr_output) |s| allocator.free(s);

        const term = child.wait() catch return ZfsError.InternalError;
        if (term.Exited != 0) {
            if (stderr_output) |stderr| {
                std.debug.print("zfs create -p failed: {s}\n", .{stderr});
            }
            return ZfsError.Unknown;
        }
    }

    /// Destroy a dataset (and optionally its children)
    /// SECURITY: Uses direct execve instead of shell to prevent command injection
    pub fn destroyDataset(
        self: *ZfsHandle,
        allocator: std.mem.Allocator,
        path: []const u8,
        recursive: bool,
    ) !void {
        // SECURITY: Validate dataset name to prevent command injection
        if (!isValidDatasetName(path)) {
            return ZfsError.InvalidDatasetName;
        }

        // For recursive destruction (including snapshots), use direct execve
        // as the libzfs API doesn't reliably handle all cases
        if (recursive) {
            // Use direct execve - no shell involved
            var child = std.process.Child.init(
                &[_][]const u8{ "zfs", "destroy", "-rf", path },
                allocator,
            );
            child.stderr_behavior = .Pipe;
            child.stdout_behavior = .Ignore;
            try child.spawn();
            const stderr_output = child.stderr.?.reader().readAllAlloc(allocator, 4096) catch "";
            defer if (stderr_output.len > 0) allocator.free(stderr_output);
            const term = child.wait() catch return ZfsError.InternalError;
            if (term.Exited != 0) {
                if (stderr_output.len > 0) {
                    std.debug.print("    ZFS error: {s}", .{stderr_output});
                }
                return ZfsError.Unknown;
            }
            return;
        }

        const c_path = try allocator.dupeZ(u8, path);
        defer allocator.free(c_path);

        self.mutex.lock();
        defer self.mutex.unlock();

        const zhp = c.zfs_open(self.handle, c_path.ptr, c.ZFS_TYPE_DATASET) orelse {
            const errno_val = c.libzfs_errno(self.handle);
            return libzfsErrorToZig(errno_val);
        };
        defer c.zfs_close(zhp);

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

        self.mutex.lock();
        defer self.mutex.unlock();

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

        self.mutex.lock();
        defer self.mutex.unlock();

        // Open the snapshot to get a dataset handle
        const snap_handle = c.zfs_open(self.handle, c_snap.ptr, c.ZFS_TYPE_SNAPSHOT) orelse {
            const errno_val = c.libzfs_errno(self.handle);
            return libzfsErrorToZig(errno_val);
        };
        defer c.zfs_close(snap_handle);

        const result = c.zfs_clone(snap_handle, c_target.ptr, nvlist);

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

        const c_prop = try allocator.dupeZ(u8, property);
        defer allocator.free(c_prop);

        const c_value = try allocator.dupeZ(u8, value);
        defer allocator.free(c_value);

        self.mutex.lock();
        defer self.mutex.unlock();

        const zhp = c.zfs_open(self.handle, c_path.ptr, c.ZFS_TYPE_DATASET) orelse {
            const errno_val = c.libzfs_errno(self.handle);
            return libzfsErrorToZig(errno_val);
        };
        defer c.zfs_close(zhp);

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

        const c_prop = try allocator.dupeZ(u8, property);
        defer allocator.free(c_prop);

        // Try to get user properties first using libzfs (with mutex protection)
        {
            self.mutex.lock();
            defer self.mutex.unlock();

            const zhp = c.zfs_open(self.handle, c_path.ptr, c.ZFS_TYPE_DATASET) orelse {
                const errno_val = c.libzfs_errno(self.handle);
                return libzfsErrorToZig(errno_val);
            };
            defer c.zfs_close(zhp);

            const nvl = c.zfs_get_user_props(zhp);

            if (nvl != null) {
                var prop_val: [*c]const u8 = undefined;
                if (c.nvlist_lookup_string(nvl, c_prop.ptr, &prop_val) == 0) {
                    const value_len = std.mem.len(prop_val);
                    return try allocator.dupe(u8, prop_val[0..value_len]);
                }
            }
        }

        // SECURITY: Validate inputs to prevent command injection
        if (!isValidDatasetName(path)) {
            return ZfsError.InvalidDatasetName;
        }
        if (!isValidPropertyName(property)) {
            return ZfsError.InvalidPropertyName;
        }

        // Fallback: use direct execve for standard ZFS properties (no shell)
        var child = std.process.Child.init(
            &[_][]const u8{ "zfs", "get", "-H", "-o", "value", property, path },
            allocator,
        );
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

        // Allocate options outside mutex block to ensure lifetime extends to zfs_mount call
        const c_opts: ?[:0]u8 = if (options) |opts| try allocator.dupeZ(u8, opts) else null;
        defer if (c_opts) |o| allocator.free(o);

        self.mutex.lock();
        defer self.mutex.unlock();

        const zhp = c.zfs_open(self.handle, c_path.ptr, c.ZFS_TYPE_FILESYSTEM) orelse {
            const errno_val = c.libzfs_errno(self.handle);
            return libzfsErrorToZig(errno_val);
        };
        defer c.zfs_close(zhp);

        const c_options: [*c]const u8 = if (c_opts) |o| o.ptr else null;
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

        self.mutex.lock();
        defer self.mutex.unlock();

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
            _ = child.wait() catch |err| {
                errors.logProcessCleanup(@src(), err, "zfs receive");
            };
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
            _ = child.wait() catch |err| {
                errors.logProcessCleanup(@src(), err, "zfs send");
            };
            return ZfsError.InternalError;
        };
        defer file.close();

        // Read from child stdout and write to file
        const stdout = child.stdout orelse {
            _ = child.wait() catch |err| {
                errors.logProcessCleanup(@src(), err, "zfs send");
            };
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
            _ = child.wait() catch |err| {
                errors.logProcessCleanup(@src(), err, "zfs send incremental");
            };
            return ZfsError.InternalError;
        };
        defer file.close();

        const stdout = child.stdout orelse {
            _ = child.wait() catch |err| {
                errors.logProcessCleanup(@src(), err, "zfs send incremental");
            };
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
    /// SECURITY: Uses direct execve instead of shell to prevent command injection
    pub fn listChildDatasets(
        self: *ZfsHandle,
        allocator: std.mem.Allocator,
        parent: []const u8,
    ) ![][]const u8 {
        _ = self;

        // SECURITY: Validate dataset name to prevent command injection
        if (!isValidDatasetName(parent)) {
            return ZfsError.InvalidDatasetName;
        }

        // Use direct execve (no shell) for zfs list
        var child = std.process.Child.init(
            &[_][]const u8{ "zfs", "list", "-H", "-o", "name", "-r", "-d", "1", parent },
            allocator,
        );
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
        // Skip the first line (parent dataset) - equivalent to tail -n +2
        var datasets: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (datasets.items) |item| {
                allocator.free(item);
            }
            datasets.deinit();
        }

        var lines = std.mem.splitScalar(u8, stdout, '\n');
        var first_line = true;
        while (lines.next()) |line| {
            // Skip the first line (parent dataset itself)
            if (first_line) {
                first_line = false;
                continue;
            }

            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0) continue;

            // Extract just the last component (child name)
            if (std.mem.lastIndexOf(u8, trimmed, "/")) |idx| {
                const child_name = trimmed[idx + 1 ..];
                if (child_name.len > 0) {
                    try datasets.append(allocator, try allocator.dupe(u8, child_name));
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
        zfs.destroyDataset(allocator, test_dataset, false) catch |err| {
            errors.logZfsCleanup(@src(), err, test_dataset);
        };
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

// ============================================================================
// Phase 51: Shell Command Injection Prevention Tests
// ============================================================================

test "isValidDatasetName accepts valid names" {
    // Valid dataset names
    try std.testing.expect(isValidDatasetName("zroot"));
    try std.testing.expect(isValidDatasetName("zroot/axiom"));
    try std.testing.expect(isValidDatasetName("zroot/axiom/store/pkg"));
    try std.testing.expect(isValidDatasetName("tank/data-set_1.0"));
    try std.testing.expect(isValidDatasetName("pool:special"));
    try std.testing.expect(isValidDatasetName("dataset@snapshot"));
    try std.testing.expect(isValidDatasetName("dataset#bookmark"));
}

test "isValidDatasetName rejects shell metacharacters" {
    // Reject shell command injection attempts
    try std.testing.expect(!isValidDatasetName("zroot; rm -rf /"));
    try std.testing.expect(!isValidDatasetName("zroot$(whoami)"));
    try std.testing.expect(!isValidDatasetName("zroot`whoami`"));
    try std.testing.expect(!isValidDatasetName("zroot|cat /etc/passwd"));
    try std.testing.expect(!isValidDatasetName("zroot&background"));
    try std.testing.expect(!isValidDatasetName("zroot>output"));
    try std.testing.expect(!isValidDatasetName("zroot<input"));
    try std.testing.expect(!isValidDatasetName("zroot\necho pwned"));
    try std.testing.expect(!isValidDatasetName("zroot'quoted'"));
    try std.testing.expect(!isValidDatasetName("zroot\"double\""));
}

test "isValidDatasetName rejects special cases" {
    // Reject empty name
    try std.testing.expect(!isValidDatasetName(""));

    // Reject NUL byte
    try std.testing.expect(!isValidDatasetName("zroot\x00evil"));

    // Reject spaces (not valid in ZFS dataset names)
    try std.testing.expect(!isValidDatasetName("zroot name"));
}

test "isValidPropertyName accepts valid names" {
    // Valid property names
    try std.testing.expect(isValidPropertyName("compression"));
    try std.testing.expect(isValidPropertyName("mountpoint"));
    try std.testing.expect(isValidPropertyName("user:custom"));
    try std.testing.expect(isValidPropertyName("com.company.prop"));
    try std.testing.expect(isValidPropertyName("atime"));
}

test "isValidPropertyName rejects invalid names" {
    // Reject shell injection attempts
    try std.testing.expect(!isValidPropertyName("compression; rm -rf /"));
    try std.testing.expect(!isValidPropertyName("$(whoami)"));
    try std.testing.expect(!isValidPropertyName(""));
    try std.testing.expect(!isValidPropertyName("prop name"));
    try std.testing.expect(!isValidPropertyName("prop/path"));
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

    // Invalid: build_id with reserved name (..)
    try std.testing.expectError(PathValidationError.ReservedName, validator.buildPackagePath("bash", "5.2.0", 1, ".."));
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
        zfs.destroyDataset(allocator, clone_target, false) catch |err| {
            errors.logZfsCleanup(@src(), err, clone_target);
        };
    }
    if (try zfs.datasetExists(allocator, test_dataset, .filesystem)) {
        zfs.destroyDataset(allocator, test_dataset, true) catch |err| {
            errors.logZfsCleanup(@src(), err, test_dataset);
        };
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

// ============================================================================
// Phase 30: Thread-Safe libzfs Operations
// ============================================================================

/// Thread-safe ZFS error context
/// Stores per-operation error information to avoid race conditions
pub const ZfsErrorContext = struct {
    /// Last error code
    last_error: ?ZfsError = null,
    /// Last error message (static buffer to avoid allocation)
    message_buf: [256]u8 = [_]u8{0} ** 256,
    /// Length of valid error message
    message_len: usize = 0,

    /// Set error information
    pub fn setError(self: *ZfsErrorContext, err: ZfsError, msg: []const u8) void {
        self.last_error = err;
        const copy_len = @min(msg.len, self.message_buf.len - 1);
        @memcpy(self.message_buf[0..copy_len], msg[0..copy_len]);
        self.message_buf[copy_len] = 0;
        self.message_len = copy_len;
    }

    /// Get error message
    pub fn getMessage(self: *const ZfsErrorContext) []const u8 {
        return self.message_buf[0..self.message_len];
    }

    /// Clear error state
    pub fn clear(self: *ZfsErrorContext) void {
        self.last_error = null;
        self.message_len = 0;
    }
};

/// Thread-safe wrapper for ZFS operations
/// libzfs is NOT thread-safe, so all operations must be serialized
pub const ThreadSafeZfs = struct {
    /// Global mutex for all libzfs operations
    /// Since libzfs uses global state internally, we must serialize all access
    global_lock: std.Thread.Mutex = .{},

    /// The underlying ZFS handle (lazily initialized)
    handle: ?*c.libzfs_handle_t = null,

    /// Handle initialization lock (separate from operation lock)
    init_lock: std.Thread.Mutex = .{},

    /// Reference count for handle lifecycle management
    ref_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    /// Whether the handle has been initialized
    initialized: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    /// Per-thread error context using thread ID as key
    /// Note: In production, consider using thread-local storage
    error_contexts: std.AutoHashMap(std.Thread.Id, ZfsErrorContext) = undefined,
    error_lock: std.Thread.Mutex = .{},

    /// Initialize the thread-safe ZFS wrapper
    pub fn init(allocator: std.mem.Allocator) ThreadSafeZfs {
        return .{
            .error_contexts = std.AutoHashMap(std.Thread.Id, ZfsErrorContext).init(allocator),
        };
    }

    /// Clean up all resources
    pub fn deinit(self: *ThreadSafeZfs) void {
        self.global_lock.lock();
        defer self.global_lock.unlock();

        if (self.handle) |h| {
            c.libzfs_fini(h);
            self.handle = null;
        }

        self.error_lock.lock();
        defer self.error_lock.unlock();
        self.error_contexts.deinit();

        self.initialized.store(false, .release);
    }

    /// Get or create the libzfs handle (thread-safe)
    fn getHandle(self: *ThreadSafeZfs) ZfsError!*c.libzfs_handle_t {
        // Fast path: handle already initialized
        if (self.initialized.load(.acquire)) {
            return self.handle orelse ZfsError.InitFailed;
        }

        // Slow path: need to initialize
        self.init_lock.lock();
        defer self.init_lock.unlock();

        // Double-check after acquiring lock
        if (self.initialized.load(.acquire)) {
            return self.handle orelse ZfsError.InitFailed;
        }

        // Initialize libzfs
        const h = c.libzfs_init() orelse return ZfsError.InitFailed;
        self.handle = h;
        self.initialized.store(true, .release);

        return h;
    }

    /// Acquire a reference to the ZFS handle
    /// Must be paired with releaseRef()
    pub fn acquireRef(self: *ThreadSafeZfs) void {
        _ = self.ref_count.fetchAdd(1, .acquire);
    }

    /// Release a reference to the ZFS handle
    pub fn releaseRef(self: *ThreadSafeZfs) void {
        _ = self.ref_count.fetchSub(1, .release);
    }

    /// Get the current reference count (for debugging/monitoring)
    pub fn getRefCount(self: *const ThreadSafeZfs) u32 {
        return self.ref_count.load(.acquire);
    }

    /// Get error context for current thread
    fn getErrorContext(self: *ThreadSafeZfs) *ZfsErrorContext {
        const tid = std.Thread.getCurrentId();

        self.error_lock.lock();
        defer self.error_lock.unlock();

        const result = self.error_contexts.getOrPut(tid) catch {
            // If allocation fails, return a static error context
            const S = struct {
                var fallback: ZfsErrorContext = .{};
            };
            return &S.fallback;
        };

        if (result.found_existing) {
            return result.value_ptr;
        } else {
            result.value_ptr.* = .{};
            return result.value_ptr;
        }
    }

    /// Execute a ZFS operation with proper locking
    /// This is the core method that ensures thread safety
    pub fn withLock(self: *ThreadSafeZfs, comptime func: anytype, args: anytype) ZfsError!@typeInfo(@TypeOf(func)).@"fn".return_type.? {
        self.global_lock.lock();
        defer self.global_lock.unlock();

        const handle = try self.getHandle();

        // Clear error context before operation
        const err_ctx = self.getErrorContext();
        err_ctx.clear();

        // Call the function with the handle prepended to args
        return @call(.auto, func, .{handle} ++ args);
    }

    /// Create a scoped operation for compound ZFS operations
    /// Holds the lock for the duration of the scope
    pub fn scopedOperation(self: *ThreadSafeZfs) ScopedOperation {
        return ScopedOperation.init(self);
    }

    /// Scoped ZFS operation with RAII-style cleanup
    /// Use this for compound operations that need multiple libzfs calls
    pub const ScopedOperation = struct {
        zfs: *ThreadSafeZfs,
        lock_held: bool,
        handle: ?*c.libzfs_handle_t,

        pub fn init(zfs: *ThreadSafeZfs) ScopedOperation {
            return .{
                .zfs = zfs,
                .lock_held = false,
                .handle = null,
            };
        }

        /// Begin the scoped operation (acquires lock)
        pub fn begin(self: *ScopedOperation) ZfsError!*c.libzfs_handle_t {
            if (self.lock_held) {
                // Already holding lock, just return handle
                return self.handle orelse ZfsError.InitFailed;
            }

            self.zfs.global_lock.lock();
            self.lock_held = true;

            const h = self.zfs.getHandle() catch |err| {
                self.zfs.global_lock.unlock();
                self.lock_held = false;
                return err;
            };

            self.handle = h;

            // Clear error context
            const err_ctx = self.zfs.getErrorContext();
            err_ctx.clear();

            return h;
        }

        /// End the scoped operation (releases lock)
        pub fn end(self: *ScopedOperation) void {
            if (self.lock_held) {
                self.zfs.global_lock.unlock();
                self.lock_held = false;
                self.handle = null;
            }
        }

        /// RAII cleanup - automatically called when scope ends
        pub fn deinit(self: *ScopedOperation) void {
            self.end();
        }

        /// Get the handle (must have called begin() first)
        pub fn getHandle(self: *const ScopedOperation) ZfsError!*c.libzfs_handle_t {
            return self.handle orelse ZfsError.InitFailed;
        }

        /// Check if operation is active (lock held)
        pub fn isActive(self: *const ScopedOperation) bool {
            return self.lock_held;
        }
    };

    // ========================================================================
    // Thread-safe wrappers for common ZFS operations
    // ========================================================================

    /// Check if a dataset exists (thread-safe)
    pub fn datasetExists(
        self: *ThreadSafeZfs,
        allocator: std.mem.Allocator,
        path: []const u8,
        dataset_type: DatasetType,
    ) !bool {
        self.global_lock.lock();
        defer self.global_lock.unlock();

        const handle = try self.getHandle();

        const c_path = try allocator.dupeZ(u8, path);
        defer allocator.free(c_path);

        const exists = c.zfs_dataset_exists(handle, c_path.ptr, @intFromEnum(dataset_type));
        return exists != 0;
    }

    /// Create a new filesystem dataset (thread-safe)
    pub fn createDataset(
        self: *ThreadSafeZfs,
        allocator: std.mem.Allocator,
        path: []const u8,
        props: ?DatasetProperties,
    ) !void {
        self.global_lock.lock();
        defer self.global_lock.unlock();

        const handle = try self.getHandle();

        const c_path = try allocator.dupeZ(u8, path);
        defer allocator.free(c_path);

        var nvlist: ?*c.nvlist_t = null;
        if (props) |p| {
            nvlist = try p.toNvlist(allocator);
        }
        defer if (nvlist) |list| c.nvlist_free(list);

        const result = c.zfs_create(
            handle,
            c_path.ptr,
            c.ZFS_TYPE_FILESYSTEM,
            nvlist,
        );

        if (result != 0) {
            const errno_val = c.libzfs_errno(handle);
            const err = libzfsErrorToZig(errno_val);
            const err_ctx = self.getErrorContext();
            err_ctx.setError(err, "failed to create dataset");
            return err;
        }
    }

    /// Destroy a dataset (thread-safe)
    pub fn destroyDataset(
        self: *ThreadSafeZfs,
        allocator: std.mem.Allocator,
        path: []const u8,
        recursive: bool,
    ) !void {
        self.global_lock.lock();
        defer self.global_lock.unlock();

        const handle = try self.getHandle();

        const c_path = try allocator.dupeZ(u8, path);
        defer allocator.free(c_path);

        const zhp = c.zfs_open(handle, c_path.ptr, c.ZFS_TYPE_DATASET) orelse {
            const errno_val = c.libzfs_errno(handle);
            return libzfsErrorToZig(errno_val);
        };
        defer c.zfs_close(zhp);

        // FreeBSD's libzfs zfs_destroy takes a defer flag, not recursive
        // Recursive destruction would require iterating children with zfs_iter_filesystems
        // TODO: Implement recursive deletion if needed
        _ = recursive; // Mark as used
        const result = c.zfs_destroy(zhp, 0);

        if (result != 0) {
            const errno_val = c.libzfs_errno(handle);
            return libzfsErrorToZig(errno_val);
        }
    }

    /// Create a snapshot (thread-safe)
    pub fn snapshot(
        self: *ThreadSafeZfs,
        allocator: std.mem.Allocator,
        dataset: []const u8,
        snap_name: []const u8,
        recursive: bool,
    ) !void {
        self.global_lock.lock();
        defer self.global_lock.unlock();

        const handle = try self.getHandle();

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
        const result = c.zfs_snapshot(handle, c_path.ptr, @intCast(flags), nvlist);

        if (result != 0) {
            const errno_val = c.libzfs_errno(handle);
            return libzfsErrorToZig(errno_val);
        }
    }

    /// Clone a snapshot (thread-safe)
    pub fn clone(
        self: *ThreadSafeZfs,
        allocator: std.mem.Allocator,
        snap_path: []const u8,
        target: []const u8,
        props: ?DatasetProperties,
    ) !void {
        self.global_lock.lock();
        defer self.global_lock.unlock();

        const handle = try self.getHandle();

        const c_snap = try allocator.dupeZ(u8, snap_path);
        defer allocator.free(c_snap);

        const c_target = try allocator.dupeZ(u8, target);
        defer allocator.free(c_target);

        var nvlist: ?*c.nvlist_t = null;
        if (props) |p| {
            nvlist = try p.toNvlist(allocator);
        }
        defer if (nvlist) |list| c.nvlist_free(list);

        const result = c.zfs_clone(handle, c_snap.ptr, c_target.ptr, nvlist);

        if (result != 0) {
            const errno_val = c.libzfs_errno(handle);
            return libzfsErrorToZig(errno_val);
        }
    }

    /// Set a property on a dataset (thread-safe)
    pub fn setProperty(
        self: *ThreadSafeZfs,
        allocator: std.mem.Allocator,
        path: []const u8,
        property: []const u8,
        value: []const u8,
    ) !void {
        self.global_lock.lock();
        defer self.global_lock.unlock();

        const handle = try self.getHandle();

        const c_path = try allocator.dupeZ(u8, path);
        defer allocator.free(c_path);

        const zhp = c.zfs_open(handle, c_path.ptr, c.ZFS_TYPE_DATASET) orelse {
            const errno_val = c.libzfs_errno(handle);
            return libzfsErrorToZig(errno_val);
        };
        defer c.zfs_close(zhp);

        const c_prop = try allocator.dupeZ(u8, property);
        defer allocator.free(c_prop);

        const c_value = try allocator.dupeZ(u8, value);
        defer allocator.free(c_value);

        const result = c.zfs_prop_set(zhp, c_prop.ptr, c_value.ptr);

        if (result != 0) {
            const errno_val = c.libzfs_errno(handle);
            return libzfsErrorToZig(errno_val);
        }
    }

    /// Mount a dataset (thread-safe)
    pub fn mount(
        self: *ThreadSafeZfs,
        allocator: std.mem.Allocator,
        path: []const u8,
        options: ?[]const u8,
    ) !void {
        self.global_lock.lock();
        defer self.global_lock.unlock();

        const handle = try self.getHandle();

        const c_path = try allocator.dupeZ(u8, path);
        defer allocator.free(c_path);

        const zhp = c.zfs_open(handle, c_path.ptr, c.ZFS_TYPE_FILESYSTEM) orelse {
            const errno_val = c.libzfs_errno(handle);
            return libzfsErrorToZig(errno_val);
        };
        defer c.zfs_close(zhp);

        // Allocate options outside if block to ensure lifetime extends to zfs_mount call
        const c_opts: ?[:0]u8 = if (options) |opts| try allocator.dupeZ(u8, opts) else null;
        defer if (c_opts) |o| allocator.free(o);

        const c_options: [*c]const u8 = if (c_opts) |o| o.ptr else null;
        const result = c.zfs_mount(zhp, c_options, 0);

        if (result != 0) {
            const errno_val = c.libzfs_errno(handle);
            return libzfsErrorToZig(errno_val);
        }
    }

    /// Unmount a dataset (thread-safe)
    pub fn unmount(
        self: *ThreadSafeZfs,
        allocator: std.mem.Allocator,
        path: []const u8,
        force: bool,
    ) !void {
        self.global_lock.lock();
        defer self.global_lock.unlock();

        const handle = try self.getHandle();

        const c_path = try allocator.dupeZ(u8, path);
        defer allocator.free(c_path);

        const zhp = c.zfs_open(handle, c_path.ptr, c.ZFS_TYPE_FILESYSTEM) orelse {
            const errno_val = c.libzfs_errno(handle);
            return libzfsErrorToZig(errno_val);
        };
        defer c.zfs_close(zhp);

        const flags: c_int = if (force) c.MS_FORCE else 0;
        const result = c.zfs_unmount(zhp, null, flags);

        if (result != 0) {
            const errno_val = c.libzfs_errno(handle);
            return libzfsErrorToZig(errno_val);
        }
    }
};

/// Global thread-safe ZFS instance
/// Use this singleton for all ZFS operations in multi-threaded contexts
/// Thread-safe: Uses atomic operations with proper memory ordering for the
/// double-checked locking pattern to work correctly on all architectures.
var global_thread_safe_zfs: std.atomic.Value(?*ThreadSafeZfs) = std.atomic.Value(?*ThreadSafeZfs).init(null);
var global_zfs_init_lock: std.Thread.Mutex = .{};

/// Get the global thread-safe ZFS instance
/// Thread-safe: Uses double-checked locking with proper atomic memory ordering
pub fn getGlobalThreadSafeZfs(allocator: std.mem.Allocator) !*ThreadSafeZfs {
    // Fast path: already initialized (acquire semantics ensure we see fully initialized object)
    if (global_thread_safe_zfs.load(.acquire)) |zfs| {
        return zfs;
    }

    // Slow path: need to initialize
    global_zfs_init_lock.lock();
    defer global_zfs_init_lock.unlock();

    // Double-check after acquiring lock
    if (global_thread_safe_zfs.load(.acquire)) |zfs| {
        return zfs;
    }

    // Allocate and initialize
    const zfs = try allocator.create(ThreadSafeZfs);
    zfs.* = ThreadSafeZfs.init(allocator);

    // Release semantics ensure all initialization is visible before the pointer
    global_thread_safe_zfs.store(zfs, .release);

    return zfs;
}

/// Clean up the global thread-safe ZFS instance
/// Call this during program shutdown
/// Thread-safe: Uses atomic operations with proper memory ordering
pub fn deinitGlobalThreadSafeZfs(allocator: std.mem.Allocator) void {
    global_zfs_init_lock.lock();
    defer global_zfs_init_lock.unlock();

    if (global_thread_safe_zfs.load(.acquire)) |zfs| {
        zfs.deinit();
        allocator.destroy(zfs);
        global_thread_safe_zfs.store(null, .release);
    }
}

// ============================================================================
// Thread-Safe ZFS Tests
// ============================================================================

test "ThreadSafeZfs basic initialization" {
    const _allocator = std.testing.allocator;

    var zfs = ThreadSafeZfs.init(_allocator);
    defer zfs.deinit();

    // Should start with no references
    try std.testing.expectEqual(@as(u32, 0), zfs.getRefCount());

    // Acquire and release reference
    zfs.acquireRef();
    try std.testing.expectEqual(@as(u32, 1), zfs.getRefCount());

    zfs.releaseRef();
    try std.testing.expectEqual(@as(u32, 0), zfs.getRefCount());
}

test "ScopedOperation lifecycle" {
    const _allocator = std.testing.allocator;

    var zfs = ThreadSafeZfs.init(_allocator);
    defer zfs.deinit();

    // Create scoped operation
    var op = zfs.scopedOperation();
    defer op.deinit();

    // Initially not active
    try std.testing.expect(!op.isActive());

    // Begin operation (may fail if libzfs not available in test environment)
    _ = op.begin() catch |err| {
        // Expected in environments without libzfs
        try std.testing.expectEqual(ZfsError.InitFailed, err);
        return;
    };

    // Now active
    try std.testing.expect(op.isActive());

    // End operation
    op.end();
    try std.testing.expect(!op.isActive());
}

test "ZfsErrorContext operations" {
    var ctx = ZfsErrorContext{};

    // Initially no error
    try std.testing.expectEqual(@as(?ZfsError, null), ctx.last_error);
    try std.testing.expectEqual(@as(usize, 0), ctx.getMessage().len);

    // Set an error
    ctx.setError(ZfsError.DatasetNotFound, "test error message");
    try std.testing.expectEqual(ZfsError.DatasetNotFound, ctx.last_error.?);
    try std.testing.expectEqualStrings("test error message", ctx.getMessage());

    // Clear error
    ctx.clear();
    try std.testing.expectEqual(@as(?ZfsError, null), ctx.last_error);
    try std.testing.expectEqual(@as(usize, 0), ctx.getMessage().len);
}

test "concurrent reference counting" {
    const _allocator = std.testing.allocator;

    var zfs = ThreadSafeZfs.init(_allocator);
    defer zfs.deinit();

    const num_threads = 10;
    const iterations = 1000;

    // Worker function that increments and decrements ref count
    const Worker = struct {
        fn run(z: *ThreadSafeZfs) void {
            for (0..iterations) |_| {
                z.acquireRef();
                // Small delay to increase contention
                std.atomic.spinLoopHint();
                z.releaseRef();
            }
        }
    };

    // Spawn threads
    var threads: [num_threads]std.Thread = undefined;
    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, Worker.run, .{&zfs});
    }

    // Wait for all threads
    for (threads) |t| {
        t.join();
    }

    // Ref count should be back to 0
    try std.testing.expectEqual(@as(u32, 0), zfs.getRefCount());
}
