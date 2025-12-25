const std = @import("std");
const config = @import("config.zig");

/// Setup wizard errors
pub const SetupError = error{
    /// ZFS is not available
    ZfsNotAvailable,
    /// Root privileges required
    RootRequired,
    /// Pool does not exist
    PoolNotFound,
    /// Dataset already exists
    DatasetExists,
    /// Failed to create dataset
    CreateFailed,
    /// Failed to set property
    PropertyFailed,
    /// Failed to create directory
    DirectoryFailed,
    /// Operation cancelled by user
    Cancelled,
    /// General setup failure
    SetupFailed,
    OutOfMemory,
};

/// Setup status for existing installation
pub const SetupStatus = struct {
    pool_exists: bool = false,
    base_dataset_exists: bool = false,
    store_dataset_exists: bool = false,
    profiles_dataset_exists: bool = false,
    env_dataset_exists: bool = false,
    builds_dataset_exists: bool = false,
    mountpoint_correct: bool = false,
    config_dir_exists: bool = false,
    cache_dir_exists: bool = false,

    /// Check if fully configured
    pub fn isComplete(self: SetupStatus) bool {
        return self.pool_exists and
            self.base_dataset_exists and
            self.store_dataset_exists and
            self.profiles_dataset_exists and
            self.env_dataset_exists and
            self.builds_dataset_exists and
            self.mountpoint_correct and
            self.config_dir_exists and
            self.cache_dir_exists;
    }

    /// Check if partially configured
    pub fn isPartial(self: SetupStatus) bool {
        const has_some = self.base_dataset_exists or
            self.store_dataset_exists or
            self.profiles_dataset_exists or
            self.env_dataset_exists or
            self.builds_dataset_exists;
        return has_some and !self.isComplete();
    }
};

/// Setup wizard for initializing Axiom ZFS datasets
pub const SetupWizard = struct {
    allocator: std.mem.Allocator,
    pool: []const u8,
    dataset: []const u8,
    mountpoint: []const u8,
    config_dir: []const u8,
    cache_dir: []const u8,
    interactive: bool,
    force: bool,

    /// Initialize setup wizard with defaults
    pub fn init(allocator: std.mem.Allocator) SetupWizard {
        return .{
            .allocator = allocator,
            .pool = config.DEFAULT_POOL,
            .dataset = config.DEFAULT_DATASET,
            .mountpoint = config.DEFAULT_MOUNTPOINT,
            .config_dir = config.DEFAULT_CONFIG_DIR,
            .cache_dir = config.DEFAULT_CACHE_DIR,
            .interactive = true,
            .force = false,
        };
    }

    /// Set custom pool name
    pub fn setPool(self: *SetupWizard, pool: []const u8) void {
        self.pool = pool;
    }

    /// Set custom dataset name
    pub fn setDataset(self: *SetupWizard, dataset: []const u8) void {
        self.dataset = dataset;
    }

    /// Set custom mountpoint
    pub fn setMountpoint(self: *SetupWizard, mountpoint: []const u8) void {
        self.mountpoint = mountpoint;
    }

    /// Set non-interactive mode
    pub fn setNonInteractive(self: *SetupWizard) void {
        self.interactive = false;
    }

    /// Set force mode (overwrite existing)
    pub fn setForce(self: *SetupWizard) void {
        self.force = true;
    }

    /// Check current setup status
    pub fn checkStatus(self: *SetupWizard) !SetupStatus {
        var status = SetupStatus{};

        // Check if pool exists
        status.pool_exists = self.zfsDatasetExists(self.pool);

        // Build dataset paths
        const base = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.pool, self.dataset });
        defer self.allocator.free(base);

        const store_base = try std.fmt.allocPrint(self.allocator, "{s}/store", .{base});
        defer self.allocator.free(store_base);

        const store_pkg = try std.fmt.allocPrint(self.allocator, "{s}/store/pkg", .{base});
        defer self.allocator.free(store_pkg);

        const profiles = try std.fmt.allocPrint(self.allocator, "{s}/profiles", .{base});
        defer self.allocator.free(profiles);

        const env = try std.fmt.allocPrint(self.allocator, "{s}/env", .{base});
        defer self.allocator.free(env);

        const builds = try std.fmt.allocPrint(self.allocator, "{s}/builds", .{base});
        defer self.allocator.free(builds);

        // Check each dataset
        status.base_dataset_exists = self.zfsDatasetExists(base);
        status.store_dataset_exists = self.zfsDatasetExists(store_pkg);
        status.profiles_dataset_exists = self.zfsDatasetExists(profiles);
        status.env_dataset_exists = self.zfsDatasetExists(env);
        status.builds_dataset_exists = self.zfsDatasetExists(builds);

        // Check mountpoint if base exists
        if (status.base_dataset_exists) {
            const current_mp = self.zfsGetProperty(base, "mountpoint") catch null;
            if (current_mp) |mp| {
                defer self.allocator.free(mp);
                status.mountpoint_correct = std.mem.eql(u8, mp, self.mountpoint);
            }
        }

        // Check directories
        status.config_dir_exists = self.directoryExists(self.config_dir);
        status.cache_dir_exists = self.directoryExists(self.cache_dir);

        return status;
    }

    /// Run the setup wizard
    pub fn run(self: *SetupWizard) !void {
        std.debug.print("\n", .{});
        std.debug.print("===========================================\n", .{});
        std.debug.print("        Axiom Setup Wizard\n", .{});
        std.debug.print("===========================================\n", .{});
        std.debug.print("\n", .{});

        // Check for root privileges
        if (!self.isRoot()) {
            std.debug.print("Error: Setup requires root privileges.\n", .{});
            std.debug.print("Please run: sudo axiom setup\n", .{});
            return SetupError.RootRequired;
        }

        // Check if ZFS is available
        if (!self.zfsAvailable()) {
            std.debug.print("Error: ZFS is not available on this system.\n", .{});
            std.debug.print("Please install ZFS first:\n", .{});
            std.debug.print("  pkg install openzfs\n", .{});
            return SetupError.ZfsNotAvailable;
        }

        // Check current status
        const status = try self.checkStatus();

        if (status.isComplete()) {
            std.debug.print("Axiom is already fully configured!\n", .{});
            std.debug.print("\n", .{});
            self.printStatus(status);
            std.debug.print("\nRun 'axiom help' to get started.\n", .{});
            return;
        }

        if (!status.pool_exists) {
            std.debug.print("Error: ZFS pool '{s}' does not exist.\n", .{self.pool});
            std.debug.print("\n", .{});
            std.debug.print("Available pools:\n", .{});
            try self.listPools();
            std.debug.print("\n", .{});
            std.debug.print("To use a different pool, run:\n", .{});
            std.debug.print("  axiom setup --pool <pool-name>\n", .{});
            return SetupError.PoolNotFound;
        }

        if (status.isPartial() and !self.force) {
            std.debug.print("Warning: Axiom is partially configured.\n", .{});
            std.debug.print("\n", .{});
            self.printStatus(status);
            std.debug.print("\n", .{});
            std.debug.print("To continue setup, run:\n", .{});
            std.debug.print("  axiom setup --force\n", .{});
            std.debug.print("\n", .{});
            std.debug.print("Or to start fresh, first clean up:\n", .{});

            const base = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.pool, self.dataset });
            defer self.allocator.free(base);
            std.debug.print("  zfs destroy -r {s}\n", .{base});
            return SetupError.DatasetExists;
        }

        // Show configuration
        std.debug.print("Configuration:\n", .{});
        std.debug.print("  Pool:       {s}\n", .{self.pool});
        std.debug.print("  Dataset:    {s}/{s}\n", .{ self.pool, self.dataset });
        std.debug.print("  Mountpoint: {s}\n", .{self.mountpoint});
        std.debug.print("  Config dir: {s}\n", .{self.config_dir});
        std.debug.print("  Cache dir:  {s}\n", .{self.cache_dir});
        std.debug.print("\n", .{});

        // Confirm with user in interactive mode
        if (self.interactive) {
            std.debug.print("This will create the following ZFS datasets:\n", .{});
            std.debug.print("  {s}/{s}           (mountpoint: {s})\n", .{ self.pool, self.dataset, self.mountpoint });
            std.debug.print("  {s}/{s}/store     (mountpoint: {s}/store)\n", .{ self.pool, self.dataset, self.mountpoint });
            std.debug.print("  {s}/{s}/store/pkg (mountpoint: {s}/store/pkg)\n", .{ self.pool, self.dataset, self.mountpoint });
            std.debug.print("  {s}/{s}/profiles  (mountpoint: {s}/profiles)\n", .{ self.pool, self.dataset, self.mountpoint });
            std.debug.print("  {s}/{s}/env       (mountpoint: {s}/env)\n", .{ self.pool, self.dataset, self.mountpoint });
            std.debug.print("  {s}/{s}/builds    (mountpoint: {s}/builds)\n", .{ self.pool, self.dataset, self.mountpoint });
            std.debug.print("\n", .{});

            if (!try self.confirm("Proceed with setup?")) {
                std.debug.print("Setup cancelled.\n", .{});
                return SetupError.Cancelled;
            }
            std.debug.print("\n", .{});
        }

        // Perform setup
        try self.performSetup(status);

        std.debug.print("\n", .{});
        std.debug.print("===========================================\n", .{});
        std.debug.print("        Setup Complete!\n", .{});
        std.debug.print("===========================================\n", .{});
        std.debug.print("\n", .{});
        std.debug.print("Next steps:\n", .{});
        std.debug.print("\n", .{});
        std.debug.print("  Bootstrap build tools (required for building from ports):\n", .{});
        std.debug.print("    axiom ports-import devel/m4\n", .{});
        std.debug.print("    axiom ports-import devel/gmake\n", .{});
        std.debug.print("\n", .{});
        std.debug.print("  Then import packages and create your environment:\n", .{});
        std.debug.print("    1. Import packages:      axiom ports-import shells/bash\n", .{});
        std.debug.print("    2. Create a profile:     axiom profile-create myprofile\n", .{});
        std.debug.print("    3. Add packages:         axiom profile-add-package myprofile bash\n", .{});
        std.debug.print("    4. Resolve dependencies: axiom resolve myprofile\n", .{});
        std.debug.print("    5. Create environment:   axiom realize myenv myprofile\n", .{});
        std.debug.print("    6. Activate:             source {s}/env/myenv/activate\n", .{self.mountpoint});
        std.debug.print("\n", .{});
        std.debug.print("For more help: axiom help\n", .{});
    }

    /// Perform the actual setup
    fn performSetup(self: *SetupWizard, status: SetupStatus) !void {
        const base = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.pool, self.dataset });
        defer self.allocator.free(base);

        // Step 1: Create base dataset (if not exists)
        if (!status.base_dataset_exists) {
            std.debug.print("[1/8] Creating base dataset {s}...\n", .{base});
            try self.zfsCreate(base);
        } else {
            std.debug.print("[1/8] Base dataset exists, skipping...\n", .{});
        }

        // Step 2: Set mountpoint BEFORE creating children (critical!)
        if (!status.mountpoint_correct) {
            std.debug.print("[2/8] Setting mountpoint to {s}...\n", .{self.mountpoint});
            try self.zfsSetProperty(base, "mountpoint", self.mountpoint);
        } else {
            std.debug.print("[2/8] Mountpoint already correct, skipping...\n", .{});
        }

        // Step 3: Set recommended properties
        std.debug.print("[3/8] Setting ZFS properties (compression=lz4, atime=off)...\n", .{});
        self.zfsSetProperty(base, "compression", "lz4") catch {};
        self.zfsSetProperty(base, "atime", "off") catch {};

        // Step 4: Create store dataset hierarchy
        const store_base = try std.fmt.allocPrint(self.allocator, "{s}/store", .{base});
        defer self.allocator.free(store_base);

        if (!self.zfsDatasetExists(store_base)) {
            std.debug.print("[4/8] Creating store dataset...\n", .{});
            try self.zfsCreate(store_base);
        } else {
            std.debug.print("[4/8] Store dataset exists, skipping...\n", .{});
        }

        // Step 5: Create store/pkg dataset
        const store_pkg = try std.fmt.allocPrint(self.allocator, "{s}/store/pkg", .{base});
        defer self.allocator.free(store_pkg);

        if (!status.store_dataset_exists) {
            std.debug.print("[5/8] Creating package store dataset...\n", .{});
            try self.zfsCreate(store_pkg);
        } else {
            std.debug.print("[5/8] Package store dataset exists, skipping...\n", .{});
        }

        // Step 6: Create profiles dataset
        const profiles = try std.fmt.allocPrint(self.allocator, "{s}/profiles", .{base});
        defer self.allocator.free(profiles);

        if (!status.profiles_dataset_exists) {
            std.debug.print("[6/8] Creating profiles dataset...\n", .{});
            try self.zfsCreate(profiles);
        } else {
            std.debug.print("[6/8] Profiles dataset exists, skipping...\n", .{});
        }

        // Step 7: Create env and builds datasets
        const env = try std.fmt.allocPrint(self.allocator, "{s}/env", .{base});
        defer self.allocator.free(env);

        const builds = try std.fmt.allocPrint(self.allocator, "{s}/builds", .{base});
        defer self.allocator.free(builds);

        if (!status.env_dataset_exists or !status.builds_dataset_exists) {
            std.debug.print("[7/8] Creating env and builds datasets...\n", .{});
            if (!status.env_dataset_exists) try self.zfsCreate(env);
            if (!status.builds_dataset_exists) try self.zfsCreate(builds);
        } else {
            std.debug.print("[7/8] Env and builds datasets exist, skipping...\n", .{});
        }

        // Step 8: Create config directories
        std.debug.print("[8/8] Creating configuration directories...\n", .{});
        if (!status.config_dir_exists) {
            try self.createDirectory(self.config_dir);
        }
        if (!status.cache_dir_exists) {
            try self.createDirectory(self.cache_dir);
        }
    }

    /// Print current status
    fn printStatus(self: *SetupWizard, status: SetupStatus) void {
        const check = "\xe2\x9c\x93"; // Unicode checkmark
        const cross = "\xe2\x9c\x97"; // Unicode cross

        std.debug.print("Current Status:\n", .{});
        std.debug.print("  {s} Pool '{s}'\n", .{ if (status.pool_exists) check else cross, self.pool });
        std.debug.print("  {s} Base dataset ({s}/{s})\n", .{ if (status.base_dataset_exists) check else cross, self.pool, self.dataset });
        std.debug.print("  {s} Mountpoint correct ({s})\n", .{ if (status.mountpoint_correct) check else cross, self.mountpoint });
        std.debug.print("  {s} Store dataset\n", .{if (status.store_dataset_exists) check else cross});
        std.debug.print("  {s} Profiles dataset\n", .{if (status.profiles_dataset_exists) check else cross});
        std.debug.print("  {s} Env dataset\n", .{if (status.env_dataset_exists) check else cross});
        std.debug.print("  {s} Builds dataset\n", .{if (status.builds_dataset_exists) check else cross});
        std.debug.print("  {s} Config directory ({s})\n", .{ if (status.config_dir_exists) check else cross, self.config_dir });
        std.debug.print("  {s} Cache directory ({s})\n", .{ if (status.cache_dir_exists) check else cross, self.cache_dir });
    }

    /// Ask for user confirmation
    fn confirm(self: *SetupWizard, prompt: []const u8) !bool {
        _ = self;
        const stdin_file = std.fs.File.stdin();
        var stdin_buf: [256]u8 = undefined;
        const stdin = stdin_file.reader(&stdin_buf);

        std.debug.print("{s} [y/N]: ", .{prompt});

        var buf: [256]u8 = undefined;
        const line = stdin.readUntilDelimiterOrEof(&buf, '\n') catch {
            return false;
        };

        if (line) |l| {
            const trimmed = std.mem.trim(u8, l, " \t\r\n");
            return std.mem.eql(u8, trimmed, "y") or std.mem.eql(u8, trimmed, "Y") or
                std.mem.eql(u8, trimmed, "yes") or std.mem.eql(u8, trimmed, "Yes") or
                std.mem.eql(u8, trimmed, "YES");
        }
        return false;
    }

    /// Check if running as root
    fn isRoot(self: *SetupWizard) bool {
        _ = self;
        // Use C library getuid() for portability (works on FreeBSD, Linux, etc.)
        const c = @cImport({
            @cInclude("unistd.h");
        });
        const uid = c.getuid();
        return uid == 0;
    }

    /// Check if ZFS is available
    fn zfsAvailable(self: *SetupWizard) bool {
        _ = self;
        var child = std.process.Child.init(&[_][]const u8{ "zfs", "version" }, std.heap.page_allocator);
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;

        child.spawn() catch return false;
        const term = child.wait() catch return false;
        return term.Exited == 0;
    }

    /// List available ZFS pools
    fn listPools(self: *SetupWizard) !void {
        var child = std.process.Child.init(&[_][]const u8{ "zpool", "list", "-H", "-o", "name" }, self.allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;

        try child.spawn();

        const output = try child.stdout.?.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(output);

        _ = try child.wait();

        var lines = std.mem.splitScalar(u8, output, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len > 0) {
                std.debug.print("  - {s}\n", .{trimmed});
            }
        }
    }

    /// Check if a ZFS dataset exists
    fn zfsDatasetExists(self: *SetupWizard, dataset: []const u8) bool {
        var child = std.process.Child.init(&[_][]const u8{ "zfs", "list", "-H", dataset }, self.allocator);
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Ignore;

        child.spawn() catch return false;
        const term = child.wait() catch return false;
        return term.Exited == 0;
    }

    /// Create a ZFS dataset
    fn zfsCreate(self: *SetupWizard, dataset: []const u8) !void {
        var child = std.process.Child.init(&[_][]const u8{ "zfs", "create", dataset }, self.allocator);
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Pipe;

        try child.spawn();

        var stderr_output: ?[]const u8 = null;
        if (child.stderr) |stderr_pipe| {
            stderr_output = stderr_pipe.readToEndAlloc(self.allocator, 1024 * 1024) catch null;
        }
        defer if (stderr_output) |s| self.allocator.free(s);

        const term = try child.wait();
        if (term.Exited != 0) {
            if (stderr_output) |stderr| {
                std.debug.print("Error creating dataset: {s}\n", .{stderr});
            }
            return SetupError.CreateFailed;
        }
    }

    /// Set a ZFS property
    fn zfsSetProperty(self: *SetupWizard, dataset: []const u8, property: []const u8, value: []const u8) !void {
        const prop_val = try std.fmt.allocPrint(self.allocator, "{s}={s}", .{ property, value });
        defer self.allocator.free(prop_val);

        var child = std.process.Child.init(&[_][]const u8{ "zfs", "set", prop_val, dataset }, self.allocator);
        child.stdout_behavior = .Ignore;
        child.stderr_behavior = .Pipe;

        try child.spawn();

        var stderr_output: ?[]const u8 = null;
        if (child.stderr) |stderr_pipe| {
            stderr_output = stderr_pipe.readToEndAlloc(self.allocator, 1024 * 1024) catch null;
        }
        defer if (stderr_output) |s| self.allocator.free(s);

        const term = try child.wait();
        if (term.Exited != 0) {
            if (stderr_output) |stderr| {
                std.debug.print("Error setting property: {s}\n", .{stderr});
            }
            return SetupError.PropertyFailed;
        }
    }

    /// Get a ZFS property value
    fn zfsGetProperty(self: *SetupWizard, dataset: []const u8, property: []const u8) ![]u8 {
        var child = std.process.Child.init(&[_][]const u8{ "zfs", "get", "-H", "-o", "value", property, dataset }, self.allocator);
        child.stdout_behavior = .Pipe;
        child.stderr_behavior = .Ignore;

        try child.spawn();

        const output = try child.stdout.?.readToEndAlloc(self.allocator, 1024);
        errdefer self.allocator.free(output);

        const term = try child.wait();
        if (term.Exited != 0) {
            self.allocator.free(output);
            return SetupError.PropertyFailed;
        }

        // Trim and return
        const trimmed = std.mem.trim(u8, output, " \t\r\n");
        if (trimmed.len == 0) {
            self.allocator.free(output);
            return SetupError.PropertyFailed;
        }

        // Return a copy of the trimmed portion
        const result = try self.allocator.dupe(u8, trimmed);
        self.allocator.free(output);
        return result;
    }

    /// Check if a directory exists
    fn directoryExists(self: *SetupWizard, path: []const u8) bool {
        _ = self;
        var dir = std.fs.openDirAbsolute(path, .{}) catch return false;
        dir.close();
        return true;
    }

    /// Create a directory with parents
    fn createDirectory(self: *SetupWizard, path: []const u8) !void {
        _ = self;
        std.fs.makeDirAbsolute(path) catch |err| {
            if (err != error.PathAlreadyExists) {
                return SetupError.DirectoryFailed;
            }
        };
    }
};

/// Run setup from command line arguments
pub fn runSetup(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var wizard = SetupWizard.init(allocator);

    // Parse arguments
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "--pool") or std.mem.eql(u8, arg, "-p")) {
            if (i + 1 < args.len) {
                i += 1;
                wizard.setPool(args[i]);
            }
        } else if (std.mem.eql(u8, arg, "--dataset") or std.mem.eql(u8, arg, "-d")) {
            if (i + 1 < args.len) {
                i += 1;
                wizard.setDataset(args[i]);
            }
        } else if (std.mem.eql(u8, arg, "--mountpoint") or std.mem.eql(u8, arg, "-m")) {
            if (i + 1 < args.len) {
                i += 1;
                wizard.setMountpoint(args[i]);
            }
        } else if (std.mem.eql(u8, arg, "--yes") or std.mem.eql(u8, arg, "-y")) {
            wizard.setNonInteractive();
        } else if (std.mem.eql(u8, arg, "--force") or std.mem.eql(u8, arg, "-f")) {
            wizard.setForce();
        } else if (std.mem.eql(u8, arg, "--check") or std.mem.eql(u8, arg, "-c")) {
            // Just check status and exit
            const status = try wizard.checkStatus();
            wizard.printStatus(status);
            if (status.isComplete()) {
                std.debug.print("\nSetup is complete.\n", .{});
            } else if (status.isPartial()) {
                std.debug.print("\nSetup is partial. Run 'axiom setup --force' to complete.\n", .{});
            } else {
                std.debug.print("\nSetup required. Run 'axiom setup' to begin.\n", .{});
            }
            return;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printSetupHelp();
            return;
        }
    }

    try wizard.run();
}

/// Print setup help
pub fn printSetupHelp() void {
    std.debug.print(
        \\Axiom Setup Wizard
        \\
        \\Usage: axiom setup [options]
        \\
        \\Options:
        \\  -p, --pool <name>       ZFS pool to use (default: zroot)
        \\  -d, --dataset <name>    Dataset name under pool (default: axiom)
        \\  -m, --mountpoint <path> Base mountpoint (default: /axiom)
        \\  -y, --yes               Non-interactive mode (assume yes)
        \\  -f, --force             Force setup even if partially configured
        \\  -c, --check             Check current setup status
        \\  -h, --help              Show this help message
        \\
        \\Examples:
        \\  axiom setup                   # Interactive setup with defaults
        \\  axiom setup --check           # Check current status
        \\  axiom setup --pool tank       # Use 'tank' pool instead of 'zroot'
        \\  axiom setup -y                # Non-interactive with defaults
        \\  axiom setup --force           # Continue partial setup
        \\
        \\The setup wizard will create the following ZFS datasets:
        \\  <pool>/<dataset>              Base dataset
        \\  <pool>/<dataset>/store        Package store root
        \\  <pool>/<dataset>/store/pkg    Package store
        \\  <pool>/<dataset>/profiles     Profile definitions
        \\  <pool>/<dataset>/env          Realized environments
        \\  <pool>/<dataset>/builds       Build outputs
        \\
        \\And the following directories:
        \\  /etc/axiom                    Configuration files
        \\  /var/cache/axiom              Cache directory
        \\
    , .{});
}
