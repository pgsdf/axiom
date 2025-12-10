const std = @import("std");
const zfs = @import("zfs.zig");
const store = @import("store.zig");
const profile = @import("profile.zig");
const resolver = @import("resolver.zig");
const realization = @import("realization.zig");
const gc = @import("gc.zig");
const import_pkg = @import("import.zig");
const signature = @import("signature.zig");
const cache = @import("cache.zig");
const build = @import("build.zig");
const cli = @import("cli.zig");
const user = @import("user.zig");
const config = @import("config.zig");
const setup = @import("setup.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Parse command-line arguments
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // Skip program name
    const cmd_args = if (args.len > 1) args[1..] else &[_][]const u8{};

    // Handle setup command before ZFS initialization
    // Setup needs to run before ZFS is initialized since it creates the datasets
    if (cmd_args.len > 0 and std.mem.eql(u8, cmd_args[0], "setup")) {
        setup.runSetup(allocator, cmd_args[1..]) catch |err| {
            switch (err) {
                setup.SetupError.RootRequired => std.process.exit(1),
                setup.SetupError.ZfsNotAvailable => std.process.exit(1),
                setup.SetupError.PoolNotFound => std.process.exit(1),
                setup.SetupError.DatasetExists => std.process.exit(1),
                setup.SetupError.Cancelled => std.process.exit(0),
                else => {
                    std.debug.print("Setup failed: {}\n", .{err});
                    std.process.exit(1);
                },
            }
        };
        return;
    }

    // Initialize ZFS
    var zfs_handle = zfs.ZfsHandle.init() catch |err| {
        std.debug.print("Error: Failed to initialize ZFS: {}\n", .{err});
        std.debug.print("Axiom requires ZFS and root privileges.\n", .{});
        std.debug.print("\nTroubleshooting:\n", .{});
        std.debug.print("  1. Ensure ZFS/OpenZFS is installed (from FreeBSD base or ports)\n", .{});
        std.debug.print("  2. Run with root: sudo axiom <command>\n", .{});
        std.debug.print("  3. Verify datasets exist: zfs list zroot/axiom\n", .{});
        std.process.exit(1);
    };
    defer zfs_handle.deinit();

    // Initialize subsystems
    var pkg_store = try store.PackageStore.init(allocator, &zfs_handle);
    var profile_mgr = profile.ProfileManager.init(allocator, &zfs_handle);
    var res = resolver.Resolver.init(allocator, &pkg_store);
    var real = realization.RealizationEngine.init(allocator, &zfs_handle, &pkg_store);
    var collector = gc.GarbageCollector.init(allocator, &zfs_handle, &pkg_store, &profile_mgr);
    var importer = import_pkg.Importer.init(allocator, &zfs_handle, &pkg_store);
    
    // Initialize signature subsystems
    var trust_store = signature.TrustStore.init(allocator, config.DEFAULT_CONFIG_DIR ++ "/trust.toml");
    defer trust_store.deinit();
    trust_store.load() catch {}; // Ignore error if file doesn't exist

    // Load official PGSD signing keys (bundled with Axiom)
    trust_store.loadOfficialKeys() catch |err| {
        std.debug.print("Warning: Could not load official PGSD keys: {}\n", .{err});
    };

    var verifier = signature.Verifier.init(allocator, &trust_store, .warn);

    // Initialize cache subsystems
    var cache_config = cache.CacheConfig.init(allocator);
    defer cache_config.deinit();
    cache_config.loadFromFile(config.DEFAULT_CONFIG_DIR ++ "/cache.yaml") catch {}; // Ignore if doesn't exist

    var cache_client = cache.CacheClient.init(
        allocator,
        &cache_config,
        &trust_store,
        &zfs_handle,
        &pkg_store,
    );
    defer cache_client.deinit();

    // Initialize build system
    var builder = build.Builder.init(allocator, &zfs_handle, &pkg_store, &importer);

    // Initialize user context (for multi-user support)
    var user_ctx = user.UserContext.init(allocator) catch |err| {
        std.debug.print("Warning: Could not initialize user context: {}\n", .{err});
        std.debug.print("Some user-specific features may not work.\n", .{});
        // Continue without user context for basic operations
        var axiom_cli = cli.CLI.init(
            allocator,
            &zfs_handle,
            &pkg_store,
            &profile_mgr,
            &res,
            &real,
            &collector,
            &importer,
            &trust_store,
            &verifier,
            &cache_config,
            &cache_client,
            &builder,
        );
        try axiom_cli.run(cmd_args);
        return;
    };
    defer user_ctx.deinit();

    // Initialize user-scoped managers
    var user_profile_mgr = user.UserProfileManager.init(allocator, &zfs_handle, &user_ctx);
    var user_realization = user.UserRealizationEngine.init(allocator, &zfs_handle, &pkg_store, &user_ctx);
    var multi_user_mgr = user.MultiUserManager.init(allocator, &zfs_handle, &pkg_store);

    // Initialize CLI
    var axiom_cli = cli.CLI.init(
        allocator,
        &zfs_handle,
        &pkg_store,
        &profile_mgr,
        &res,
        &real,
        &collector,
        &importer,
        &trust_store,
        &verifier,
        &cache_config,
        &cache_client,
        &builder,
    );

    // Set user context for multi-user operations
    axiom_cli.setUserContext(&user_ctx, &user_profile_mgr, &user_realization, &multi_user_mgr);

    // Run command
    try axiom_cli.run(cmd_args);
}
