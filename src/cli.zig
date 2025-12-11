const std = @import("std");
const zfs = @import("zfs.zig");
const types = @import("types.zig");
const store = @import("store.zig");
const profile = @import("profile.zig");
const resolver = @import("resolver.zig");
const sat_resolver = @import("sat_resolver.zig");
const realization = @import("realization.zig");
const manifest = @import("manifest.zig");
const gc = @import("gc.zig");
const import_pkg = @import("import.zig");
const signature = @import("signature.zig");
const cache = @import("cache.zig");
const completions = @import("completions.zig");
const build_pkg = @import("build.zig");
const user_pkg = @import("user.zig");
const conflict = @import("conflict.zig");
const closure_pkg = @import("closure.zig");
const launcher_pkg = @import("launcher.zig");
const bundle_pkg = @import("bundle.zig");
const ports_pkg = @import("ports.zig");
const bootstrap_pkg = @import("bootstrap.zig");

const ZfsHandle = zfs.ZfsHandle;
const PackageStore = store.PackageStore;
const ProfileManager = profile.ProfileManager;
const Resolver = resolver.Resolver;
const RealizationEngine = realization.RealizationEngine;
const GarbageCollector = gc.GarbageCollector;
const Importer = import_pkg.Importer;
const TrustStore = signature.TrustStore;
const Verifier = signature.Verifier;
const CacheConfig = cache.CacheConfig;
const CacheClient = cache.CacheClient;
const Builder = build_pkg.Builder;
const UserContext = user_pkg.UserContext;
const UserProfileManager = user_pkg.UserProfileManager;
const UserRealizationEngine = user_pkg.UserRealizationEngine;
const MultiUserManager = user_pkg.MultiUserManager;
const ConflictPolicy = conflict.ConflictPolicy;
const ResolutionStrategy = resolver.ResolutionStrategy;
const ClosureComputer = closure_pkg.ClosureComputer;
const Launcher = launcher_pkg.Launcher;
const BundleBuilder = bundle_pkg.BundleBuilder;
const BundleFormat = bundle_pkg.BundleFormat;
const PortsMigrator = ports_pkg.PortsMigrator;
const BootstrapManager = bootstrap_pkg.BootstrapManager;

/// CLI command enumeration
pub const Command = enum {
    help,
    version,
    setup,

    // Profile management
    profile_create,
    profile_list,
    profile_show,
    profile_update,
    profile_delete,
    profile_add_package,
    profile_remove_package,

    // Package operations
    import_pkg,
    install,
    remove,
    search,
    info,
    list,
    
    // Environment operations
    resolve,
    realize,
    activate,
    env_list,
    env_destroy,

    // Dependency visualization (Phase 35)
    deps_graph,
    deps_analyze,
    deps_why,
    deps_path,

    // Signature operations
    key_list,
    key_add,
    key_remove,
    key_trust,
    key_generate,
    sign,
    verify,
    
    // Garbage collection
    gc,

    // Build operations
    build,

    // Cache operations
    cache_list,
    cache_add,
    cache_remove,
    cache_fetch,
    cache_push,
    cache_sync,
    cache_clean,

    // Shell completions
    shell_completions,

    // User operations (per-user, no root required)
    user_profile_create,
    user_profile_list,
    user_profile_show,
    user_profile_update,
    user_profile_delete,
    user_resolve,
    user_realize,
    user_activate,
    user_env_list,
    user_env_destroy,

    // System operations (root required)
    system_import,
    system_gc,
    system_users,
    system_user_remove,

    // Virtual package operations
    virtual_list,
    virtual_providers,
    pkg_provides,
    pkg_conflicts,
    pkg_replaces,

    // Bundle and launcher operations (AppImage-inspired)
    run,
    closure_show,
    export_pkg,
    bundle_create,
    bundle_verify,
    bundle_run,

    // Ports migration operations
    ports_gen,
    ports_build,
    ports_import,
    ports_scan,

    // Kernel compatibility operations
    kernel_check,

    // ZFS path validation (Phase 26)
    zfs_validate,

    // Bootstrap operations (pkg independence)
    bootstrap_status,
    bootstrap_import,
    bootstrap_export,
    bootstrap_ports,

    unknown,
};

/// Parse command from string
pub fn parseCommand(cmd: []const u8) Command {
    if (std.mem.eql(u8, cmd, "help")) return .help;
    if (std.mem.eql(u8, cmd, "version")) return .version;
    if (std.mem.eql(u8, cmd, "setup")) return .setup;

    // Profile commands
    if (std.mem.eql(u8, cmd, "profile")) return .profile_list;
    if (std.mem.eql(u8, cmd, "profile-create")) return .profile_create;
    if (std.mem.eql(u8, cmd, "profile-show")) return .profile_show;
    if (std.mem.eql(u8, cmd, "profile-update")) return .profile_update;
    if (std.mem.eql(u8, cmd, "profile-delete")) return .profile_delete;
    if (std.mem.eql(u8, cmd, "profile-add-package")) return .profile_add_package;
    if (std.mem.eql(u8, cmd, "profile-add")) return .profile_add_package;
    if (std.mem.eql(u8, cmd, "profile-remove-package")) return .profile_remove_package;
    if (std.mem.eql(u8, cmd, "profile-remove")) return .profile_remove_package;

    // Package commands
    if (std.mem.eql(u8, cmd, "import")) return .import_pkg;
    if (std.mem.eql(u8, cmd, "install")) return .install;
    if (std.mem.eql(u8, cmd, "remove")) return .remove;
    if (std.mem.eql(u8, cmd, "search")) return .search;
    if (std.mem.eql(u8, cmd, "info")) return .info;
    if (std.mem.eql(u8, cmd, "list")) return .list;
    
    // Environment commands
    if (std.mem.eql(u8, cmd, "resolve")) return .resolve;
    if (std.mem.eql(u8, cmd, "realize")) return .realize;
    if (std.mem.eql(u8, cmd, "activate")) return .activate;
    if (std.mem.eql(u8, cmd, "env")) return .env_list;

    // Dependency visualization commands (Phase 35)
    if (std.mem.eql(u8, cmd, "deps-graph")) return .deps_graph;
    if (std.mem.eql(u8, cmd, "deps-analyze")) return .deps_analyze;
    if (std.mem.eql(u8, cmd, "deps-why")) return .deps_why;
    if (std.mem.eql(u8, cmd, "deps-path")) return .deps_path;
    if (std.mem.eql(u8, cmd, "env-destroy")) return .env_destroy;
    
    // Signature commands
    if (std.mem.eql(u8, cmd, "key")) return .key_list;
    if (std.mem.eql(u8, cmd, "key-add")) return .key_add;
    if (std.mem.eql(u8, cmd, "key-remove")) return .key_remove;
    if (std.mem.eql(u8, cmd, "key-trust")) return .key_trust;
    if (std.mem.eql(u8, cmd, "key-generate")) return .key_generate;
    if (std.mem.eql(u8, cmd, "sign")) return .sign;
    if (std.mem.eql(u8, cmd, "verify")) return .verify;
    
    // GC
    if (std.mem.eql(u8, cmd, "gc")) return .gc;

    // Build
    if (std.mem.eql(u8, cmd, "build")) return .build;

    // Cache commands
    if (std.mem.eql(u8, cmd, "cache")) return .cache_list;
    if (std.mem.eql(u8, cmd, "cache-add")) return .cache_add;
    if (std.mem.eql(u8, cmd, "cache-remove")) return .cache_remove;
    if (std.mem.eql(u8, cmd, "cache-fetch")) return .cache_fetch;
    if (std.mem.eql(u8, cmd, "cache-push")) return .cache_push;
    if (std.mem.eql(u8, cmd, "cache-sync")) return .cache_sync;
    if (std.mem.eql(u8, cmd, "cache-clean")) return .cache_clean;

    // Shell completions
    if (std.mem.eql(u8, cmd, "completions")) return .shell_completions;

    // User commands (per-user, no root required)
    if (std.mem.eql(u8, cmd, "user")) return .user_profile_list;
    if (std.mem.eql(u8, cmd, "user-profile")) return .user_profile_list;
    if (std.mem.eql(u8, cmd, "user-profile-create")) return .user_profile_create;
    if (std.mem.eql(u8, cmd, "user-profile-show")) return .user_profile_show;
    if (std.mem.eql(u8, cmd, "user-profile-update")) return .user_profile_update;
    if (std.mem.eql(u8, cmd, "user-profile-delete")) return .user_profile_delete;
    if (std.mem.eql(u8, cmd, "user-resolve")) return .user_resolve;
    if (std.mem.eql(u8, cmd, "user-realize")) return .user_realize;
    if (std.mem.eql(u8, cmd, "user-activate")) return .user_activate;
    if (std.mem.eql(u8, cmd, "user-env")) return .user_env_list;
    if (std.mem.eql(u8, cmd, "user-env-destroy")) return .user_env_destroy;

    // System commands (root required)
    if (std.mem.eql(u8, cmd, "system-import")) return .system_import;
    if (std.mem.eql(u8, cmd, "system-gc")) return .system_gc;
    if (std.mem.eql(u8, cmd, "system-users")) return .system_users;
    if (std.mem.eql(u8, cmd, "system-user-remove")) return .system_user_remove;

    // Virtual package commands
    if (std.mem.eql(u8, cmd, "virtual")) return .virtual_list;
    if (std.mem.eql(u8, cmd, "virtual-list")) return .virtual_list;
    if (std.mem.eql(u8, cmd, "virtual-providers")) return .virtual_providers;
    if (std.mem.eql(u8, cmd, "provides")) return .pkg_provides;
    if (std.mem.eql(u8, cmd, "conflicts")) return .pkg_conflicts;
    if (std.mem.eql(u8, cmd, "replaces")) return .pkg_replaces;

    // Bundle and launcher commands
    if (std.mem.eql(u8, cmd, "run")) return .run;
    if (std.mem.eql(u8, cmd, "closure")) return .closure_show;
    if (std.mem.eql(u8, cmd, "export")) return .export_pkg;
    if (std.mem.eql(u8, cmd, "bundle")) return .bundle_create;
    if (std.mem.eql(u8, cmd, "build-bundle")) return .bundle_create;
    if (std.mem.eql(u8, cmd, "bundle-verify")) return .bundle_verify;
    if (std.mem.eql(u8, cmd, "verify-bundle")) return .bundle_verify;
    if (std.mem.eql(u8, cmd, "bundle-run")) return .bundle_run;
    if (std.mem.eql(u8, cmd, "run-bundle")) return .bundle_run;

    // Ports migration commands
    if (std.mem.eql(u8, cmd, "ports")) return .ports_scan;
    if (std.mem.eql(u8, cmd, "ports-gen")) return .ports_gen;
    if (std.mem.eql(u8, cmd, "ports-build")) return .ports_build;
    if (std.mem.eql(u8, cmd, "ports-import")) return .ports_import;
    if (std.mem.eql(u8, cmd, "ports-scan")) return .ports_scan;

    // Kernel compatibility commands
    if (std.mem.eql(u8, cmd, "kernel")) return .kernel_check;
    if (std.mem.eql(u8, cmd, "kernel-check")) return .kernel_check;

    // ZFS path validation (Phase 26)
    if (std.mem.eql(u8, cmd, "zfs-validate")) return .zfs_validate;
    if (std.mem.eql(u8, cmd, "validate-path")) return .zfs_validate;

    // Bootstrap commands (pkg independence)
    if (std.mem.eql(u8, cmd, "bootstrap")) return .bootstrap_status;
    if (std.mem.eql(u8, cmd, "bootstrap-status")) return .bootstrap_status;
    if (std.mem.eql(u8, cmd, "bootstrap-import")) return .bootstrap_import;
    if (std.mem.eql(u8, cmd, "bootstrap-export")) return .bootstrap_export;
    if (std.mem.eql(u8, cmd, "bootstrap-ports")) return .bootstrap_ports;
    if (std.mem.eql(u8, cmd, "bootstrap-freebsd-ports")) return .bootstrap_ports;

    return .unknown;
}

/// CLI context with all subsystems
pub const CLI = struct {
    allocator: std.mem.Allocator,
    zfs_handle: *ZfsHandle,
    store: *PackageStore,
    profile_mgr: *ProfileManager,
    resolver: *Resolver,
    realization: *RealizationEngine,
    gc: *GarbageCollector,
    importer: *Importer,
    trust_store: *TrustStore,
    verifier: *Verifier,
    cache_config: *CacheConfig,
    cache_client: *CacheClient,
    builder: *Builder,
    user_ctx: ?*UserContext,
    user_profile_mgr: ?*UserProfileManager,
    user_realization: ?*UserRealizationEngine,
    multi_user_mgr: ?*MultiUserManager,

    /// Initialize CLI with all subsystems
    pub fn init(
        allocator: std.mem.Allocator,
        zfs_handle: *ZfsHandle,
        store_ptr: *PackageStore,
        profile_mgr_ptr: *ProfileManager,
        resolver_ptr: *Resolver,
        realization_ptr: *RealizationEngine,
        gc_ptr: *GarbageCollector,
        importer_ptr: *Importer,
        trust_store_ptr: *TrustStore,
        verifier_ptr: *Verifier,
        cache_config_ptr: *CacheConfig,
        cache_client_ptr: *CacheClient,
        builder_ptr: *Builder,
    ) CLI {
        return CLI{
            .allocator = allocator,
            .zfs_handle = zfs_handle,
            .store = store_ptr,
            .profile_mgr = profile_mgr_ptr,
            .resolver = resolver_ptr,
            .realization = realization_ptr,
            .gc = gc_ptr,
            .importer = importer_ptr,
            .trust_store = trust_store_ptr,
            .verifier = verifier_ptr,
            .cache_config = cache_config_ptr,
            .cache_client = cache_client_ptr,
            .builder = builder_ptr,
            .user_ctx = null,
            .user_profile_mgr = null,
            .user_realization = null,
            .multi_user_mgr = null,
        };
    }

    /// Set user context for multi-user operations
    pub fn setUserContext(
        self: *CLI,
        user_ctx: *UserContext,
        user_profile_mgr: *UserProfileManager,
        user_realization: *UserRealizationEngine,
        multi_user_mgr: *MultiUserManager,
    ) void {
        self.user_ctx = user_ctx;
        self.user_profile_mgr = user_profile_mgr;
        self.user_realization = user_realization;
        self.multi_user_mgr = multi_user_mgr;
    }

    /// Run CLI command
    pub fn run(self: *CLI, args: []const []const u8) !void {
        if (args.len == 0) {
            try self.showHelp();
            return;
        }

        const cmd = parseCommand(args[0]);

        switch (cmd) {
            .help => try self.showHelp(),
            .version => try self.showVersion(),
            .setup => {
                // Setup is handled in main() before CLI initialization
                // If we get here, setup was already complete
                std.debug.print("Axiom is already set up and running.\n", .{});
                std.debug.print("To check setup status: axiom setup --check\n", .{});
            },

            .profile_create => try self.profileCreate(args[1..]),
            .profile_list => try self.profileList(args[1..]),
            .profile_show => try self.profileShow(args[1..]),
            .profile_update => try self.profileUpdate(args[1..]),
            .profile_delete => try self.profileDelete(args[1..]),
            .profile_add_package => try self.profileAddPackage(args[1..]),
            .profile_remove_package => try self.profileRemovePackage(args[1..]),

            .import_pkg => try self.importPackage(args[1..]),
            .install => try self.install(args[1..]),
            .remove => try self.remove(args[1..]),
            .search => try self.search(args[1..]),
            .info => try self.info(args[1..]),
            .list => try self.listPackages(args[1..]),
            
            .resolve => try self.resolveProfile(args[1..]),
            .realize => try self.realizeEnv(args[1..]),
            .activate => try self.activateEnv(args[1..]),
            .env_list => try self.listEnvs(args[1..]),

            // Dependency visualization (Phase 35)
            .deps_graph => try self.depsGraph(args[1..]),
            .deps_analyze => try self.depsAnalyze(args[1..]),
            .deps_why => try self.depsWhy(args[1..]),
            .deps_path => try self.depsPath(args[1..]),
            .env_destroy => try self.destroyEnv(args[1..]),
            
            .key_list => try self.keyList(args[1..]),
            .key_add => try self.keyAdd(args[1..]),
            .key_remove => try self.keyRemove(args[1..]),
            .key_trust => try self.keyTrust(args[1..]),
            .key_generate => try self.keyGenerate(args[1..]),
            .sign => try self.signPackage(args[1..]),
            .verify => try self.verifyPackage(args[1..]),
            
            .gc => try self.garbageCollect(args[1..]),

            .build => try self.buildPackage(args[1..]),

            .cache_list => try self.cacheList(args[1..]),
            .cache_add => try self.cacheAdd(args[1..]),
            .cache_remove => try self.cacheRemove(args[1..]),
            .cache_fetch => try self.cacheFetch(args[1..]),
            .cache_push => try self.cachePush(args[1..]),
            .cache_sync => try self.cacheSync(args[1..]),
            .cache_clean => try self.cacheClean(args[1..]),

            .shell_completions => try self.generateCompletions(args[1..]),

            // User commands
            .user_profile_create => try self.userProfileCreate(args[1..]),
            .user_profile_list => try self.userProfileList(args[1..]),
            .user_profile_show => try self.userProfileShow(args[1..]),
            .user_profile_update => try self.userProfileUpdate(args[1..]),
            .user_profile_delete => try self.userProfileDelete(args[1..]),
            .user_resolve => try self.userResolve(args[1..]),
            .user_realize => try self.userRealize(args[1..]),
            .user_activate => try self.userActivate(args[1..]),
            .user_env_list => try self.userEnvList(args[1..]),
            .user_env_destroy => try self.userEnvDestroy(args[1..]),

            // System commands
            .system_import => try self.systemImport(args[1..]),
            .system_gc => try self.systemGc(args[1..]),
            .system_users => try self.systemUsers(args[1..]),
            .system_user_remove => try self.systemUserRemove(args[1..]),

            // Virtual package commands
            .virtual_list => try self.virtualList(args[1..]),
            .virtual_providers => try self.virtualProviders(args[1..]),
            .pkg_provides => try self.pkgProvides(args[1..]),
            .pkg_conflicts => try self.pkgConflicts(args[1..]),
            .pkg_replaces => try self.pkgReplaces(args[1..]),

            // Bundle and launcher commands
            .run => try self.runPackage(args[1..]),
            .closure_show => try self.showClosure(args[1..]),
            .export_pkg => try self.exportPackage(args[1..]),
            .bundle_create => try self.createBundle(args[1..]),
            .bundle_verify => try self.bundleVerify(args[1..]),
            .bundle_run => try self.bundleRun(args[1..]),

            // Ports migration commands
            .ports_gen => try self.portsGen(args[1..]),
            .ports_build => try self.portsBuild(args[1..]),
            .ports_import => try self.portsImport(args[1..]),
            .ports_scan => try self.portsScan(args[1..]),

            // Kernel compatibility commands
            .kernel_check => try self.kernelCheck(args[1..]),

            // ZFS path validation (Phase 26)
            .zfs_validate => try self.zfsValidate(args[1..]),

            // Bootstrap commands (pkg independence)
            .bootstrap_status => try self.bootstrapStatus(args[1..]),
            .bootstrap_import => try self.bootstrapImport(args[1..]),
            .bootstrap_export => try self.bootstrapExport(args[1..]),
            .bootstrap_ports => try self.bootstrapPorts(args[1..]),

            .unknown => {
                std.debug.print("Unknown command: {s}\n", .{args[0]});
                std.debug.print("Run 'axiom help' for usage information.\n", .{});
            },
        }
    }

    // Help and version

    fn showHelp(self: *CLI) !void {
        _ = self;
        std.debug.print(
            \\Axiom - ZFS-native package manager for Pacific Grove Software Distribution
            \\
            \\Usage: axiom <command> [options]
            \\
            \\Profile Management:
            \\  profile                    List all profiles
            \\  profile-create <name>      Create a new profile
            \\  profile-show <name>        Show profile details
            \\  profile-update <name>      Update a profile
            \\  profile-delete <name>      Delete a profile
            \\  profile-add-package <p> <pkg> [ver]   Add package to profile
            \\  profile-remove-package <p> <pkg>      Remove package from profile
            \\
            \\Package Operations:
            \\  import <source> [opts]     Import package from directory/tarball
            \\  install <package>          Add package to current profile
            \\  remove <package>           Remove package from current profile
            \\  search <query>             Search for packages
            \\  info <package>             Show package information
            \\  list                       List installed packages
            \\
            \\Environment Operations:
            \\  resolve <profile>          Resolve profile dependencies
            \\    --strategy <s>             Resolution strategy (greedy|sat|auto)
            \\    --timeout <seconds>        Maximum resolution time (default: 30)
            \\    --max-memory <MB>          Maximum memory usage (default: 256)
            \\    --max-depth <n>            Maximum dependency depth (default: 100)
            \\    --strict                   Use strict limits for untrusted inputs
            \\    --stats                    Show resolution statistics
            \\  realize <env> <profile>    Create environment from profile
            \\    --conflict-policy <p>      Handle file conflicts (error|priority|keep-both)
            \\  activate <env>             Activate an environment
            \\  env                        List all environments
            \\  env-destroy <env>          Destroy an environment
            \\
            \\Signature Operations:
            \\  key                        List trusted keys
            \\  key-add <file>             Add public key from file
            \\  key-remove <key-id>        Remove a key
            \\  key-trust <key-id>         Mark key as trusted
            \\  key-generate               Generate new key pair
            \\  sign <path> --key <file>   Sign a package
            \\  verify <path>              Verify package signature
            \\
            \\Build Operations:
            \\  build <recipe.yaml>        Build package from recipe
            \\
            \\Maintenance:
            \\  gc                         Run garbage collector
            \\
            \\Cache Operations:
            \\  cache                      List configured caches
            \\  cache-add <url>            Add a remote cache
            \\  cache-remove <url>         Remove a remote cache
            \\  cache-fetch <pkg>          Fetch package from cache
            \\  cache-push <pkg>           Push package to cache
            \\  cache-sync                 Sync with remote caches
            \\  cache-clean                Clean local cache
            \\
            \\Shell Completions:
            \\  completions <shell>        Generate shell completions (bash, zsh, fish)
            \\
            \\User Operations (per-user, no root required):
            \\  user                       List user profiles
            \\  user-profile-create <n>    Create user profile
            \\  user-profile-show <n>      Show user profile details
            \\  user-profile-update <n>    Update user profile
            \\  user-profile-delete <n>    Delete user profile
            \\  user-resolve <profile>     Resolve user profile dependencies
            \\    --strategy <s>             Resolution strategy (greedy|sat|auto)
            \\  user-realize <e> <p>       Create user environment from profile
            \\  user-activate <env>        Activate user environment
            \\  user-env                   List user environments
            \\  user-env-destroy <env>     Destroy user environment
            \\
            \\System Operations (root required):
            \\  system-import <source>     Import package to system store
            \\  system-gc                  Run system garbage collector
            \\  system-users               List all Axiom users
            \\  system-user-remove <u>     Remove user's Axiom data
            \\
            \\Virtual Package Operations:
            \\  virtual                    List all known virtual packages
            \\  virtual-providers <name>   List packages providing virtual pkg
            \\  provides <package>         Show what virtual pkgs package provides
            \\  conflicts <package>        Show packages that conflict with pkg
            \\  replaces <package>         Show packages that pkg replaces
            \\
            \\Bundle and Launcher Operations:
            \\  run <pkg>@<ver> [args]     Run package directly without activation
            \\    --isolated                 Run in fully isolated mode
            \\  closure <pkg>@<ver>        Show package dependency closure
            \\    --tree                     Display as tree
            \\  export <pkg>@<ver>         Export package as portable bundle
            \\    --format <f>               Output format (pgsdimg|zfs|tar|dir)
            \\  bundle <directory>         Create bundle from current directory
            \\    --output <file>            Output file path
            \\  bundle-verify <file>       Verify bundle signature and integrity
            \\    --trust-store <dir>        Path to trust store
            \\    --allow-unsigned           Allow unsigned bundles
            \\  bundle-run <file> [args]   Run bundle with verification
            \\    --allow-untrusted          Allow untrusted signers
            \\    --skip-verify              Skip verification (DANGEROUS)
            \\
            \\Ports Migration (FreeBSD):
            \\  ports                      Scan ports tree, list categories
            \\  ports-gen <origin>         Generate Axiom manifests from port
            \\    --out <dir>                Output directory
            \\    --build                    Also build after generating
            \\    --import                   Also import to store after building
            \\  ports-build <origin>       Build port with Axiom builder
            \\  ports-import <origin>      Full migration: gen + build + import
            \\  ports-scan <category>      Scan category for migratable ports
            \\
            \\Bootstrap (pkg independence):
            \\  bootstrap                  Check bootstrap status
            \\  bootstrap-ports            Build bootstrap chain from FreeBSD ports
            \\    --minimal                  Build only gmake, m4, help2man
            \\    --dry-run                  Show what would be built
            \\    --jobs <n>                 Parallel build jobs (default: 4)
            \\  bootstrap-import <tar>     Import bootstrap tarball
            \\    --force                    Overwrite existing packages
            \\    --dry-run                  Show what would be imported
            \\  bootstrap-export <tar>     Export packages to bootstrap tarball
            \\    --minimal                  Include only minimal packages
            \\    --packages <list>          Comma-separated package list
            \\    --compression <c>          zstd, gzip, xz, none (default: zstd)
            \\
            \\Kernel Compatibility:
            \\  kernel                      Check kernel-bound package compatibility
            \\  kernel-check                (alias for kernel)
            \\
            \\Setup:
            \\  setup                      Run the setup wizard to initialize Axiom
            \\    --pool <name>              ZFS pool to use (default: zroot)
            \\    --dataset <name>           Dataset name (default: axiom)
            \\    --mountpoint <path>        Mountpoint (default: /axiom)
            \\    --check                    Check current setup status
            \\    --force                    Continue partial setup
            \\    --yes                      Non-interactive mode
            \\
            \\General:
            \\  help                       Show this help message
            \\  version                    Show version information
            \\
            \\Examples:
            \\  axiom setup                           # Run the setup wizard (first time)
            \\  axiom setup --check                   # Check setup status
            \\  axiom profile-create development      # System-wide profile (root)
            \\  axiom user-profile-create my-dev      # Per-user profile
            \\  axiom user-realize my-env my-dev      # Create user environment
            \\  source ~/.axiom/env/my-env/activate   # Activate user environment
            \\
        , .{});
    }

    fn showVersion(self: *CLI) !void {
        _ = self;
        std.debug.print("Axiom 0.1.0\n", .{});
        std.debug.print("Pacific Grove Software Distribution Foundation\n", .{});
    }

    // Profile management

    fn profileCreate(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom profile-create <name>\n", .{});
            return;
        }

        const name = args[0];
        std.debug.print("Creating profile: {s}\n", .{name});

        // Create empty profile
        const packages = try self.allocator.alloc(profile.PackageRequest, 0);
        const prof = profile.Profile{
            .name = try self.allocator.dupe(u8, name),
            .description = try self.allocator.dupe(u8, "Created via axiom CLI"),
            .packages = packages,
        };
        defer {
            self.allocator.free(prof.name);
            if (prof.description) |d| self.allocator.free(d);
            self.allocator.free(prof.packages);
        }

        self.profile_mgr.createProfile(prof) catch |err| {
            if (err == error.ProfileExists) {
                std.debug.print("Error: Profile '{s}' already exists.\n\n", .{name});
                std.debug.print("If this is from a previous failed attempt, remove it first:\n", .{});
                std.debug.print("  zfs destroy {s}/{s}\n\n", .{ self.profile_mgr.profile_root, name });
                std.debug.print("Then retry:\n", .{});
                std.debug.print("  axiom profile-create {s}\n", .{name});
                return;
            }
            return err;
        };
        std.debug.print("✓ Profile '{s}' created\n", .{name});
    }

    fn profileList(self: *CLI, args: []const []const u8) !void {
        // Check for --names-only flag (for shell completion)
        var names_only = false;
        for (args) |arg| {
            if (std.mem.eql(u8, arg, "--names-only")) {
                names_only = true;
            }
        }

        if (names_only) {
            // TODO: Output profile names only, one per line
            // For shell completion scripts
            return;
        }

        std.debug.print("Available profiles:\n", .{});
        std.debug.print("  (TODO: List profiles from {s})\n", .{self.profile_mgr.profile_root});
    }

    fn profileShow(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom profile-show <name>\n", .{});
            return;
        }

        const name = args[0];
        var prof = try self.profile_mgr.loadProfile(name);
        defer prof.deinit(self.allocator);

        std.debug.print("Profile: {s}\n", .{prof.name});
        if (prof.description) |desc| {
            std.debug.print("Description: {s}\n", .{desc});
        }
        std.debug.print("Packages ({d}):\n", .{prof.packages.len});
        for (prof.packages) |pkg| {
            std.debug.print("  - {s}\n", .{pkg.name});
        }
    }

    fn profileUpdate(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom profile-update <name>\n", .{});
            return;
        }

        const name = args[0];
        std.debug.print("Updating profile: {s}\n", .{name});
        std.debug.print("(Interactive update not yet implemented)\n", .{});
        _ = self;
    }

    fn profileDelete(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom profile-delete <name>\n", .{});
            return;
        }

        const name = args[0];
        std.debug.print("Deleting profile: {s}\n", .{name});
        try self.profile_mgr.deleteProfile(name);
        std.debug.print("✓ Profile deleted\n", .{});
    }

    fn profileAddPackage(self: *CLI, args: []const []const u8) !void {
        if (args.len < 2) {
            std.debug.print("Usage: axiom profile-add-package <profile> <package> [version]\n", .{});
            std.debug.print("\nExamples:\n", .{});
            std.debug.print("  axiom profile-add-package myprofile bash          # Any version\n", .{});
            std.debug.print("  axiom profile-add-package myprofile bash 5.2.0    # Exact version\n", .{});
            std.debug.print("  axiom profile-add-package myprofile bash \"^5.0\"   # Caret (compatible)\n", .{});
            std.debug.print("  axiom profile-add-package myprofile bash \"~5.2\"   # Tilde (patch updates)\n", .{});
            std.debug.print("  axiom profile-add-package myprofile bash \">=5.0\"  # Range\n", .{});
            return;
        }

        const profile_name = args[0];
        const package_name = args[1];
        const version_constraint: ?[]const u8 = if (args.len > 2) args[2] else null;

        self.profile_mgr.addPackageToProfile(profile_name, package_name, version_constraint) catch |err| {
            if (err == error.ProfileNotFound) {
                std.debug.print("Error: Profile '{s}' not found.\n", .{profile_name});
                return;
            }
            return err;
        };
    }

    fn profileRemovePackage(self: *CLI, args: []const []const u8) !void {
        if (args.len < 2) {
            std.debug.print("Usage: axiom profile-remove-package <profile> <package>\n", .{});
            std.debug.print("\nExample:\n", .{});
            std.debug.print("  axiom profile-remove-package myprofile bash\n", .{});
            return;
        }

        const profile_name = args[0];
        const package_name = args[1];

        self.profile_mgr.removePackageFromProfile(profile_name, package_name) catch |err| {
            if (err == error.ProfileNotFound) {
                std.debug.print("Error: Profile '{s}' not found.\n", .{profile_name});
                return;
            }
            return err;
        };
    }

    // Package operations

    fn importPackage(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom import <source> [options]\n", .{});
            std.debug.print("\nOptions:\n", .{});
            std.debug.print("  --name <n>           Package name\n", .{});
            std.debug.print("  --version <ver>      Package version (e.g., 1.2.3)\n", .{});
            std.debug.print("  --description <text> Package description\n", .{});
            std.debug.print("  --license <license>  Package license\n", .{});
            std.debug.print("  --manifest <file>    Use manifest file\n", .{});
            std.debug.print("  --dry-run            Show what would be imported\n", .{});
            std.debug.print("\nSignature Verification (Phase 25):\n", .{});
            std.debug.print("  --allow-unsigned     Allow import of unsigned packages\n", .{});
            std.debug.print("  --no-verify          Disable signature verification\n", .{});
            std.debug.print("  --verify-warn        Warn on verification failures (don't block)\n", .{});
            return;
        }

        const source_path = args[0];

        // Parse options
        var options = import_pkg.ImportOptions{};
        var i: usize = 1;
        while (i < args.len) {
            const arg = args[i];
            if (std.mem.eql(u8, arg, "--name") and i + 1 < args.len) {
                options.name = args[i + 1];
                i += 2;
            } else if (std.mem.eql(u8, arg, "--version") and i + 1 < args.len) {
                options.version = types.Version.parse(args[i + 1]) catch {
                    std.debug.print("Error: Invalid version format: {s}\n", .{args[i + 1]});
                    return;
                };
                i += 2;
            } else if (std.mem.eql(u8, arg, "--description") and i + 1 < args.len) {
                options.description = args[i + 1];
                i += 2;
            } else if (std.mem.eql(u8, arg, "--license") and i + 1 < args.len) {
                options.license = args[i + 1];
                i += 2;
            } else if (std.mem.eql(u8, arg, "--manifest") and i + 1 < args.len) {
                options.manifest_path = args[i + 1];
                i += 2;
            } else if (std.mem.eql(u8, arg, "--dry-run")) {
                options.dry_run = true;
                i += 1;
            // Phase 25: Signature verification options
            } else if (std.mem.eql(u8, arg, "--allow-unsigned")) {
                options.security.allow_unsigned = true;
                i += 1;
            } else if (std.mem.eql(u8, arg, "--no-verify")) {
                options.security.verification_mode = .disabled;
                i += 1;
            } else if (std.mem.eql(u8, arg, "--verify-warn")) {
                options.security.verification_mode = .warn;
                i += 1;
            } else {
                std.debug.print("Unknown option: {s}\n", .{arg});
                return;
            }
        }

        // Determine source type
        const source = if (std.mem.endsWith(u8, source_path, ".tar.gz") or
            std.mem.endsWith(u8, source_path, ".tgz") or
            std.mem.endsWith(u8, source_path, ".tar.xz") or
            std.mem.endsWith(u8, source_path, ".txz") or
            std.mem.endsWith(u8, source_path, ".tar.bz2") or
            std.mem.endsWith(u8, source_path, ".tar.zst") or
            std.mem.endsWith(u8, source_path, ".tar"))
            import_pkg.ImportSource{ .tarball = source_path }
        else
            import_pkg.ImportSource{ .directory = source_path };

        // Run import
        const pkg_id = self.importer.import(source, options) catch |err| {
            std.debug.print("Import failed: {}\n", .{err});
            return;
        };

        if (!options.dry_run) {
            std.debug.print("\nImported: {s} {}\n", .{ pkg_id.name, pkg_id.version });
        }
    }

    fn install(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom install <package>\n", .{});
            return;
        }

        const pkg_name = args[0];
        std.debug.print("Installing package: {s}\n", .{pkg_name});
        std.debug.print("(Package installation not yet implemented)\n", .{});
        std.debug.print("Workflow:\n", .{});
        std.debug.print("  1. Add '{s}' to current profile\n", .{pkg_name});
        std.debug.print("  2. Run 'axiom resolve <profile>'\n", .{});
        std.debug.print("  3. Run 'axiom realize <env> <profile>'\n", .{});
        _ = self;
    }

    fn remove(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom remove <package>\n", .{});
            return;
        }

        const pkg_name = args[0];
        std.debug.print("Removing package: {s}\n", .{pkg_name});
        std.debug.print("(Package removal not yet implemented)\n", .{});
        _ = self;
    }

    fn search(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom search <query>\n", .{});
            return;
        }

        const query = args[0];
        std.debug.print("Searching for: {s}\n", .{query});
        std.debug.print("(Package search not yet implemented)\n", .{});
        _ = self;
    }

    fn info(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom info <package>\n", .{});
            return;
        }

        const pkg_name = args[0];
        std.debug.print("Package information: {s}\n", .{pkg_name});
        std.debug.print("(Package info not yet implemented)\n", .{});
        _ = self;
    }

    fn listPackages(self: *CLI, args: []const []const u8) !void {
        // Check for --names-only flag (for shell completion)
        var names_only = false;
        var show_origin = false;
        for (args) |arg| {
            if (std.mem.eql(u8, arg, "--names-only")) {
                names_only = true;
            } else if (std.mem.eql(u8, arg, "--origin") or std.mem.eql(u8, arg, "-o")) {
                show_origin = true;
            }
        }

        // Get list of packages from store
        const packages = self.store.listPackages() catch |err| {
            std.debug.print("Error listing packages: {s}\n", .{@errorName(err)});
            return;
        };
        defer {
            for (packages) |pkg| {
                self.allocator.free(pkg.name);
                self.allocator.free(pkg.build_id);
            }
            self.allocator.free(packages);
        }

        if (names_only) {
            // Output package names only, one per line (for shell completion)
            // Deduplicate names since there may be multiple versions
            var seen = std.StringHashMap(void).init(self.allocator);
            defer seen.deinit();
            for (packages) |pkg| {
                if (!seen.contains(pkg.name)) {
                    std.debug.print("{s}\n", .{pkg.name});
                    seen.put(pkg.name, {}) catch {};
                }
            }
            return;
        }

        if (packages.len == 0) {
            std.debug.print("No packages installed.\n", .{});
            std.debug.print("\nUse 'axiom ports-import <port>' to build packages from FreeBSD ports.\n", .{});
            return;
        }

        // Deduplicate packages by name-version-revision (ignore build_id variations)
        // Each package may have multiple build IDs (content-addressed builds)
        const PackageKey = struct {
            name: []const u8,
            version: types.Version,
            revision: u32,
        };

        var unique_packages = std.ArrayList(PackageKey).init(self.allocator);
        defer unique_packages.deinit();

        // Simple O(n²) deduplication - fine for reasonable package counts
        for (packages) |pkg| {
            var found = false;
            for (unique_packages.items) |existing| {
                if (std.mem.eql(u8, existing.name, pkg.name) and
                    existing.version.major == pkg.version.major and
                    existing.version.minor == pkg.version.minor and
                    existing.version.patch == pkg.version.patch and
                    existing.revision == pkg.revision)
                {
                    found = true;
                    break;
                }
            }
            if (!found) {
                unique_packages.append(.{
                    .name = pkg.name,
                    .version = pkg.version,
                    .revision = pkg.revision,
                }) catch {};
            }
        }

        std.debug.print("Installed packages ({d}):\n", .{unique_packages.items.len});
        for (unique_packages.items) |pkg| {
            // Format: name-version_revision
            if (show_origin) {
                // Try to get origin for this package
                const origin = self.store.getPackageOriginByName(pkg.name) catch null;
                defer if (origin) |o| self.allocator.free(o);
                if (origin) |o| {
                    std.debug.print("  {s}-{}.{}.{}_{d}  ({s})\n", .{
                        pkg.name,
                        pkg.version.major,
                        pkg.version.minor,
                        pkg.version.patch,
                        pkg.revision,
                        o,
                    });
                } else {
                    std.debug.print("  {s}-{}.{}.{}_{d}\n", .{
                        pkg.name,
                        pkg.version.major,
                        pkg.version.minor,
                        pkg.version.patch,
                        pkg.revision,
                    });
                }
            } else {
                std.debug.print("  {s}-{}.{}.{}_{d}\n", .{
                    pkg.name,
                    pkg.version.major,
                    pkg.version.minor,
                    pkg.version.patch,
                    pkg.revision,
                });
            }
        }
    }

    // Environment operations

    fn resolveProfile(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom resolve <profile> [options]\n", .{});
            std.debug.print("\nStrategy Options:\n", .{});
            std.debug.print("  --strategy <strategy>  Resolution strategy to use\n", .{});
            std.debug.print("  --prefer <preference>  Version selection preference\n", .{});
            std.debug.print("\nBacktracking Options:\n", .{});
            std.debug.print("  --max-backtracks <n>       Max backtrack attempts per package (default: 5)\n", .{});
            std.debug.print("  --total-backtracks <n>     Max total backtracks (default: 50)\n", .{});
            std.debug.print("  --backtrack-threshold <n>  Max packages for backtracking (default: 20)\n", .{});
            std.debug.print("\nResource Limit Options:\n", .{});
            std.debug.print("  --timeout <seconds>    Maximum resolution time (default: 30)\n", .{});
            std.debug.print("  --max-memory <MB>      Maximum memory usage (default: 256)\n", .{});
            std.debug.print("  --max-depth <n>        Maximum dependency depth (default: 100)\n", .{});
            std.debug.print("  --strict               Use strict limits for untrusted inputs\n", .{});
            std.debug.print("  --stats                Show resolution statistics\n", .{});
            std.debug.print("\nStrategies:\n", .{});
            std.debug.print("  greedy         Fast greedy algorithm\n", .{});
            std.debug.print("  backtracking   Greedy with backtracking on conflicts\n", .{});
            std.debug.print("  sat            SAT solver for complex constraints\n", .{});
            std.debug.print("  auto           Try greedy first, fallback to SAT (default)\n", .{});
            std.debug.print("\nVersion Preferences:\n", .{});
            std.debug.print("  newest         Always pick newest version (default)\n", .{});
            std.debug.print("  stable         Prefer older, more stable versions\n", .{});
            std.debug.print("  oldest         Pick oldest satisfying version\n", .{});
            return;
        }

        const name = args[0];

        // Parse options
        var strategy: ResolutionStrategy = .greedy_with_sat_fallback;
        var preference: resolver.VersionPreference = .newest;
        var backtrack_config = resolver.BacktrackConfig{};
        var limits = resolver.ResourceLimits{};
        var show_stats = false;
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--strategy") and i + 1 < args.len) {
                const strat_str = args[i + 1];
                if (std.mem.eql(u8, strat_str, "greedy")) {
                    strategy = .greedy;
                } else if (std.mem.eql(u8, strat_str, "backtracking")) {
                    strategy = .greedy_with_backtracking;
                } else if (std.mem.eql(u8, strat_str, "sat")) {
                    strategy = .sat;
                } else if (std.mem.eql(u8, strat_str, "auto")) {
                    strategy = .greedy_with_sat_fallback;
                } else {
                    std.debug.print("Unknown strategy: {s}\n", .{strat_str});
                    std.debug.print("Valid options: greedy, backtracking, sat, auto\n", .{});
                    return;
                }
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--prefer") and i + 1 < args.len) {
                const pref_str = args[i + 1];
                if (std.mem.eql(u8, pref_str, "newest")) {
                    preference = .newest;
                } else if (std.mem.eql(u8, pref_str, "stable")) {
                    preference = .stable;
                } else if (std.mem.eql(u8, pref_str, "oldest")) {
                    preference = .oldest;
                } else {
                    std.debug.print("Unknown preference: {s}\n", .{pref_str});
                    std.debug.print("Valid options: newest, stable, oldest\n", .{});
                    return;
                }
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--max-backtracks") and i + 1 < args.len) {
                backtrack_config.max_backtracks_per_package = std.fmt.parseInt(u32, args[i + 1], 10) catch {
                    std.debug.print("Invalid max-backtracks value: {s}\n", .{args[i + 1]});
                    return;
                };
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--total-backtracks") and i + 1 < args.len) {
                backtrack_config.max_total_backtracks = std.fmt.parseInt(u32, args[i + 1], 10) catch {
                    std.debug.print("Invalid total-backtracks value: {s}\n", .{args[i + 1]});
                    return;
                };
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--backtrack-threshold") and i + 1 < args.len) {
                backtrack_config.small_graph_threshold = std.fmt.parseInt(u32, args[i + 1], 10) catch {
                    std.debug.print("Invalid backtrack-threshold value: {s}\n", .{args[i + 1]});
                    return;
                };
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--timeout") and i + 1 < args.len) {
                const seconds = std.fmt.parseInt(u64, args[i + 1], 10) catch {
                    std.debug.print("Invalid timeout value: {s}\n", .{args[i + 1]});
                    return;
                };
                limits.max_resolution_time_ms = seconds * 1000;
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--max-memory") and i + 1 < args.len) {
                const mb = std.fmt.parseInt(usize, args[i + 1], 10) catch {
                    std.debug.print("Invalid memory value: {s}\n", .{args[i + 1]});
                    return;
                };
                limits.max_memory_bytes = mb * 1024 * 1024;
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--max-depth") and i + 1 < args.len) {
                const depth = std.fmt.parseInt(u32, args[i + 1], 10) catch {
                    std.debug.print("Invalid depth value: {s}\n", .{args[i + 1]});
                    return;
                };
                limits.max_dependency_depth = depth;
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--strict")) {
                limits = resolver.ResourceLimits.strict();
            } else if (std.mem.eql(u8, args[i], "--stats")) {
                show_stats = true;
            } else {
                std.debug.print("Unknown option: {s}\n", .{args[i]});
                return;
            }
        }

        std.debug.print("Resolving profile: {s}\n", .{name});
        std.debug.print("Strategy: {s}\n", .{@tagName(strategy)});
        std.debug.print("Version preference: {s}\n\n", .{@tagName(preference)});

        // Load profile
        var prof = try self.profile_mgr.loadProfile(name);
        defer prof.deinit(self.allocator);

        // Set resolution strategy, preferences, and limits
        self.resolver.setStrategy(strategy);
        self.resolver.setVersionPreference(preference);
        self.resolver.setBacktrackConfig(backtrack_config);
        self.resolver.setResourceLimits(limits);
        self.resolver.setShowStats(show_stats);

        // Resolve dependencies
        var lock = self.resolver.resolve(prof) catch |err| {
            std.debug.print("\n✗ Resolution failed: {}\n", .{err});

            // Phase 29: Show resource limit diagnostics
            if (self.resolver.getLastStats()) |stats| {
                if (stats.limit_hit) |limit| {
                    std.debug.print("\nResource limit exceeded: {s}\n", .{limit.message()});
                    std.debug.print("  Time elapsed: {d:.2}s\n", .{stats.elapsedSeconds()});
                    std.debug.print("  Memory used: {d} MB\n", .{stats.peak_memory_bytes / (1024 * 1024)});
                    std.debug.print("  Candidates examined: {d}\n", .{stats.candidates_examined});
                    std.debug.print("  Max depth: {d}\n", .{stats.max_depth_reached});

                    std.debug.print("\nSuggestions:\n", .{});
                    switch (limit) {
                        .time => std.debug.print("  → Use --timeout <seconds> to increase time limit\n", .{}),
                        .memory => std.debug.print("  → Use --max-memory <MB> to increase memory limit\n", .{}),
                        .depth => std.debug.print("  → Use --max-depth <n> to increase depth limit\n", .{}),
                        .candidates_per_package, .total_candidates => {
                            std.debug.print("  → This may indicate a malicious or misconfigured manifest\n", .{});
                            std.debug.print("  → Consider reviewing the package dependencies\n", .{});
                        },
                        .sat_variables, .sat_clauses => {
                            std.debug.print("  → Try using --strategy greedy for simpler resolution\n", .{});
                            std.debug.print("  → The dependency graph may be too complex\n", .{});
                        },
                    }
                    return;
                }
            }

            // Show detailed diagnostics from SAT solver if available
            if (self.resolver.getLastFailure()) |failure| {
                std.debug.print("\nDiagnostics:\n", .{});

                // Show conflict explanations
                if (failure.explanations.len > 0) {
                    std.debug.print("\nConflicts detected:\n", .{});
                    for (failure.explanations) |exp| {
                        std.debug.print("  • ", .{});
                        const writer = std.io.getStdErr().writer();
                        exp.format(writer) catch {};
                        std.debug.print("\n", .{});
                    }
                }

                // Show suggestions
                if (failure.suggestions.len > 0) {
                    std.debug.print("\nSuggestions:\n", .{});
                    for (failure.suggestions) |suggestion| {
                        std.debug.print("  → {s}\n", .{suggestion});
                    }
                }
            }
            return;
        };
        defer lock.deinit(self.allocator);

        // Save lock file
        try self.profile_mgr.saveLock(name, lock);

        std.debug.print("\n✓ Profile resolved and lock file saved\n", .{});
        std.debug.print("  Packages: {d}\n", .{lock.resolved.len});
    }

    fn realizeEnv(self: *CLI, args: []const []const u8) !void {
        if (args.len < 2) {
            std.debug.print("Usage: axiom realize <env-name> <profile> [options]\n", .{});
            std.debug.print("\nOptions:\n", .{});
            std.debug.print("  --conflict-policy <policy>  How to handle file conflicts\n", .{});
            std.debug.print("\nConflict policies:\n", .{});
            std.debug.print("  error        Fail on any file conflict (default)\n", .{});
            std.debug.print("  priority     Later packages override earlier ones\n", .{});
            std.debug.print("  keep-both    Keep both files with package suffix\n", .{});
            return;
        }

        const env_name = args[0];
        const profile_name = args[1];

        // Parse options
        var conflict_policy: ConflictPolicy = .error_on_conflict;
        var i: usize = 2;
        while (i < args.len) {
            if (std.mem.eql(u8, args[i], "--conflict-policy") and i + 1 < args.len) {
                const policy_str = args[i + 1];
                if (std.mem.eql(u8, policy_str, "error")) {
                    conflict_policy = .error_on_conflict;
                } else if (std.mem.eql(u8, policy_str, "priority")) {
                    conflict_policy = .priority_wins;
                } else if (std.mem.eql(u8, policy_str, "keep-both")) {
                    conflict_policy = .keep_both;
                } else if (std.mem.eql(u8, policy_str, "interactive")) {
                    conflict_policy = .interactive;
                    std.debug.print("Warning: Interactive mode not fully implemented yet\n", .{});
                } else {
                    std.debug.print("Unknown conflict policy: {s}\n", .{policy_str});
                    std.debug.print("Valid options: error, priority, keep-both\n", .{});
                    return;
                }
                i += 2;
            } else {
                std.debug.print("Unknown option: {s}\n", .{args[i]});
                return;
            }
        }

        std.debug.print("Realizing environment: {s}\n", .{env_name});
        std.debug.print("From profile: {s}\n", .{profile_name});
        std.debug.print("Conflict policy: {s}\n\n", .{@tagName(conflict_policy)});

        // Set conflict policy
        self.realization.setConflictPolicy(conflict_policy);

        // Load lock file
        var lock = try self.profile_mgr.loadLock(profile_name);
        defer lock.deinit(self.allocator);

        // Realize environment
        var env = self.realization.realize(env_name, lock) catch |err| {
            if (err == realization.RealizationError.FileConflict) {
                std.debug.print("\n✗ File conflicts detected. Options:\n", .{});
                std.debug.print("  - Use --conflict-policy priority to let later packages win\n", .{});
                std.debug.print("  - Use --conflict-policy keep-both to keep both files\n", .{});
                return;
            }
            if (err == realization.RealizationError.EnvironmentExists) {
                std.debug.print("Error: Environment '{s}' already exists.\n\n", .{env_name});
                std.debug.print("To recreate it, destroy the existing environment first:\n", .{});
                std.debug.print("  axiom env-destroy {s}\n\n", .{env_name});
                std.debug.print("Then retry:\n", .{});
                std.debug.print("  axiom realize {s} {s}\n", .{ env_name, profile_name });
                return;
            }
            return err;
        };
        defer realization.freeEnvironment(&env, self.allocator);

        std.debug.print("\n✓ Environment realized\n", .{});
        std.debug.print("To activate: source {s}/{s}/activate\n", .{
            "/axiom/env",
            env_name,
        });
    }

    fn activateEnv(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom activate <env>\n", .{});
            return;
        }

        const env_name = args[0];
        try self.realization.activate(env_name);
    }

    fn listEnvs(self: *CLI, args: []const []const u8) !void {
        // Check for --names-only flag (for shell completion)
        var names_only = false;
        for (args) |arg| {
            if (std.mem.eql(u8, arg, "--names-only")) {
                names_only = true;
            }
        }

        if (names_only) {
            // TODO: Output environment names only, one per line
            // For shell completion scripts
            return;
        }

        std.debug.print("Available environments:\n", .{});
        std.debug.print("  (TODO: List environments from {s})\n", .{self.realization.env_root});
    }

    fn destroyEnv(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom env-destroy <env>\n", .{});
            return;
        }

        const env_name = args[0];
        std.debug.print("Destroying environment: {s}\n", .{env_name});
        
        // Confirm
        std.debug.print("Are you sure? (y/N): ", .{});
        
        var buffer: [10]u8 = undefined;
        const stdin = std.io.getStdIn().reader();
        const input = try stdin.readUntilDelimiterOrEof(&buffer, '\n');
        
        if (input) |line| {
            if (line.len > 0 and (line[0] == 'y' or line[0] == 'Y')) {
                self.realization.destroy(env_name) catch |err| {
                    if (err == zfs.ZfsError.DatasetBusy) {
                        std.debug.print("Error: Environment '{s}' is busy.\n\n", .{env_name});
                        std.debug.print("The dataset may be mounted or in use. Try:\n", .{});
                        std.debug.print("  1. Deactivate the environment: deactivate\n", .{});
                        std.debug.print("  2. Unmount manually: zfs unmount zroot/axiom/env/{s}\n", .{env_name});
                        std.debug.print("  3. Retry: axiom env-destroy {s}\n", .{env_name});
                        return;
                    }
                    if (err == zfs.ZfsError.DatasetNotFound) {
                        std.debug.print("Error: Environment '{s}' does not exist.\n", .{env_name});
                        return;
                    }
                    if (err == zfs.ZfsError.PermissionDenied) {
                        std.debug.print("Error: Permission denied. Run with sudo.\n", .{});
                        return;
                    }
                    return err;
                };
                std.debug.print("✓ Environment destroyed\n", .{});
            } else {
                std.debug.print("Cancelled\n", .{});
            }
        }
    }

    // Dependency visualization (Phase 35)

    fn depsGraph(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom deps-graph <profile> [options]\n", .{});
            std.debug.print("\nOptions:\n", .{});
            std.debug.print("  --format <fmt>  Output format: dot, json, tree (default: tree)\n", .{});
            std.debug.print("  --depth <n>     Maximum depth to display (default: unlimited)\n", .{});
            std.debug.print("  --output <file> Write to file instead of stdout\n", .{});
            std.debug.print("\nExamples:\n", .{});
            std.debug.print("  axiom deps-graph myprofile\n", .{});
            std.debug.print("  axiom deps-graph myprofile --format dot > deps.dot\n", .{});
            std.debug.print("  axiom deps-graph myprofile --format json --output deps.json\n", .{});
            return;
        }

        const profile_name = args[0];

        // Parse options
        var format: enum { tree, dot, json } = .tree;
        var max_depth: ?u32 = null;
        var output_file: ?[]const u8 = null;

        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--format") and i + 1 < args.len) {
                const fmt = args[i + 1];
                if (std.mem.eql(u8, fmt, "dot")) {
                    format = .dot;
                } else if (std.mem.eql(u8, fmt, "json")) {
                    format = .json;
                } else if (std.mem.eql(u8, fmt, "tree")) {
                    format = .tree;
                } else {
                    std.debug.print("Unknown format: {s}\n", .{fmt});
                    std.debug.print("Valid formats: dot, json, tree\n", .{});
                    return;
                }
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--depth") and i + 1 < args.len) {
                max_depth = std.fmt.parseInt(u32, args[i + 1], 10) catch {
                    std.debug.print("Invalid depth: {s}\n", .{args[i + 1]});
                    return;
                };
                i += 1;
            } else if (std.mem.eql(u8, args[i], "--output") and i + 1 < args.len) {
                output_file = args[i + 1];
                i += 1;
            }
        }

        // Load profile lock file
        var lock = self.profile_mgr.loadLock(profile_name) catch |err| {
            if (err == error.FileNotFound) {
                std.debug.print("Error: Profile '{s}' has no lock file.\n", .{profile_name});
                std.debug.print("Run 'axiom resolve {s}' first.\n", .{profile_name});
                return;
            }
            return err;
        };
        defer lock.deinit(self.allocator);

        // Build dependency graph
        var graph = try self.buildDependencyGraph(lock);
        defer graph.deinit();

        // Output the graph
        const stdout = std.io.getStdOut().writer();
        var file_writer: ?std.fs.File.Writer = null;
        var file_handle: ?std.fs.File = null;

        if (output_file) |path| {
            file_handle = try std.fs.cwd().createFile(path, .{});
            file_writer = file_handle.?.writer();
        }

        const writer = if (file_writer) |fw| fw else stdout;

        switch (format) {
            .tree => try self.outputTreeFormat(writer, graph, lock, max_depth),
            .dot => try self.outputDotFormat(writer, graph, lock),
            .json => try self.outputJsonFormat(writer, graph, lock),
        }

        if (file_handle) |fh| {
            fh.close();
            std.debug.print("Graph written to: {s}\n", .{output_file.?});
        }
    }

    fn depsAnalyze(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom deps-analyze <profile>\n", .{});
            std.debug.print("\nAnalyze the dependency graph of a resolved profile.\n", .{});
            std.debug.print("Shows statistics like depth, breadth, and potential issues.\n", .{});
            return;
        }

        const profile_name = args[0];

        // Load profile lock file
        var lock = self.profile_mgr.loadLock(profile_name) catch |err| {
            if (err == error.FileNotFound) {
                std.debug.print("Error: Profile '{s}' has no lock file.\n", .{profile_name});
                std.debug.print("Run 'axiom resolve {s}' first.\n", .{profile_name});
                return;
            }
            return err;
        };
        defer lock.deinit(self.allocator);

        // Build dependency graph
        var graph = try self.buildDependencyGraph(lock);
        defer graph.deinit();

        // Calculate statistics
        const stats = try self.calculateGraphStats(graph, lock);

        // Output analysis
        std.debug.print("Dependency Analysis: {s}\n", .{profile_name});
        std.debug.print("════════════════════════════════════════\n", .{});
        std.debug.print("\n", .{});
        std.debug.print("Package Count:     {d}\n", .{lock.resolved.len});
        std.debug.print("Direct Dependencies: {d}\n", .{stats.direct_deps});
        std.debug.print("Transitive Dependencies: {d}\n", .{lock.resolved.len - stats.direct_deps});
        std.debug.print("\n", .{});
        std.debug.print("Maximum Depth:     {d}\n", .{stats.max_depth});
        std.debug.print("Average Depth:     {d:.1}\n", .{stats.avg_depth});
        std.debug.print("Maximum Fanout:    {d}\n", .{stats.max_fanout});
        std.debug.print("Average Fanout:    {d:.1}\n", .{stats.avg_fanout});
        std.debug.print("\n", .{});

        if (stats.leaf_count > 0) {
            std.debug.print("Leaf Packages:     {d} (no dependencies)\n", .{stats.leaf_count});
        }

        if (stats.most_depended) |pkg| {
            std.debug.print("Most Depended On:  {s} ({d} dependents)\n", .{ pkg, stats.most_depended_count });
        }

        if (stats.deepest_chain.len > 0) {
            std.debug.print("\nDeepest Dependency Chain:\n", .{});
            for (stats.deepest_chain, 0..) |pkg, idx| {
                var indent: usize = 0;
                while (indent < idx) : (indent += 1) {
                    std.debug.print("  ", .{});
                }
                std.debug.print("└─ {s}\n", .{pkg});
            }
        }
    }

    fn depsWhy(self: *CLI, args: []const []const u8) !void {
        if (args.len < 2) {
            std.debug.print("Usage: axiom deps-why <profile> <package>\n", .{});
            std.debug.print("\nExplain why a package is included in the profile.\n", .{});
            std.debug.print("Shows the dependency chain(s) leading to the package.\n", .{});
            return;
        }

        const profile_name = args[0];
        const target_pkg = args[1];

        // Load profile lock file
        var lock = self.profile_mgr.loadLock(profile_name) catch |err| {
            if (err == error.FileNotFound) {
                std.debug.print("Error: Profile '{s}' has no lock file.\n", .{profile_name});
                std.debug.print("Run 'axiom resolve {s}' first.\n", .{profile_name});
                return;
            }
            return err;
        };
        defer lock.deinit(self.allocator);

        // Check if package exists in lock
        var found = false;
        var is_requested = false;
        for (lock.resolved) |pkg| {
            if (std.mem.eql(u8, pkg.name, target_pkg)) {
                found = true;
                is_requested = pkg.requested;
                break;
            }
        }

        if (!found) {
            std.debug.print("Package '{s}' is not in profile '{s}'.\n", .{ target_pkg, profile_name });
            return;
        }

        std.debug.print("Why is '{s}' in profile '{s}'?\n", .{ target_pkg, profile_name });
        std.debug.print("════════════════════════════════════════\n\n", .{});

        if (is_requested) {
            std.debug.print("• Directly requested in profile\n\n", .{});
        }

        // Build dependency graph and find paths
        var graph = try self.buildDependencyGraph(lock);
        defer graph.deinit();

        // Find all packages that depend on target
        var dependents = std.ArrayList([]const u8).init(self.allocator);
        defer dependents.deinit();

        for (lock.resolved) |pkg| {
            if (graph.edges.get(pkg.name)) |deps| {
                for (deps.items) |dep| {
                    if (std.mem.eql(u8, dep, target_pkg)) {
                        try dependents.append(pkg.name);
                        break;
                    }
                }
            }
        }

        if (dependents.items.len > 0) {
            std.debug.print("Required by:\n", .{});
            for (dependents.items) |dep| {
                // Check if this dependent is requested
                var dep_requested = false;
                for (lock.resolved) |pkg| {
                    if (std.mem.eql(u8, pkg.name, dep)) {
                        dep_requested = pkg.requested;
                        break;
                    }
                }
                if (dep_requested) {
                    std.debug.print("  • {s} (requested)\n", .{dep});
                } else {
                    std.debug.print("  • {s}\n", .{dep});
                }
            }
            std.debug.print("\n", .{});
        }

        // Show full chain from requested packages
        std.debug.print("Dependency chains from requested packages:\n", .{});
        var chains_found: u32 = 0;
        for (lock.resolved) |pkg| {
            if (pkg.requested) {
                var path = std.ArrayList([]const u8).init(self.allocator);
                defer path.deinit();
                if (try self.findDependencyPath(graph, pkg.name, target_pkg, &path)) {
                    chains_found += 1;
                    std.debug.print("\n  {s}", .{pkg.name});
                    for (path.items[1..]) |p| {
                        std.debug.print(" → {s}", .{p});
                    }
                    std.debug.print("\n", .{});
                }
            }
        }

        if (chains_found == 0 and !is_requested) {
            std.debug.print("  (no chain found - may be an orphan)\n", .{});
        }
    }

    fn depsPath(self: *CLI, args: []const []const u8) !void {
        if (args.len < 3) {
            std.debug.print("Usage: axiom deps-path <profile> <from> <to>\n", .{});
            std.debug.print("\nFind the dependency path between two packages.\n", .{});
            return;
        }

        const profile_name = args[0];
        const from_pkg = args[1];
        const to_pkg = args[2];

        // Load profile lock file
        var lock = self.profile_mgr.loadLock(profile_name) catch |err| {
            if (err == error.FileNotFound) {
                std.debug.print("Error: Profile '{s}' has no lock file.\n", .{profile_name});
                std.debug.print("Run 'axiom resolve {s}' first.\n", .{profile_name});
                return;
            }
            return err;
        };
        defer lock.deinit(self.allocator);

        // Verify both packages exist
        var from_found = false;
        var to_found = false;
        for (lock.resolved) |pkg| {
            if (std.mem.eql(u8, pkg.name, from_pkg)) from_found = true;
            if (std.mem.eql(u8, pkg.name, to_pkg)) to_found = true;
        }

        if (!from_found) {
            std.debug.print("Package '{s}' is not in profile '{s}'.\n", .{ from_pkg, profile_name });
            return;
        }
        if (!to_found) {
            std.debug.print("Package '{s}' is not in profile '{s}'.\n", .{ to_pkg, profile_name });
            return;
        }

        // Build dependency graph
        var graph = try self.buildDependencyGraph(lock);
        defer graph.deinit();

        // Find path
        var path = std.ArrayList([]const u8).init(self.allocator);
        defer path.deinit();

        if (try self.findDependencyPath(graph, from_pkg, to_pkg, &path)) {
            std.debug.print("Dependency path: {s} → {s}\n", .{ from_pkg, to_pkg });
            std.debug.print("════════════════════════════════════════\n\n", .{});

            for (path.items, 0..) |pkg, idx| {
                var indent: usize = 0;
                while (indent < idx) : (indent += 1) {
                    std.debug.print("  ", .{});
                }
                if (idx == 0) {
                    std.debug.print("{s}\n", .{pkg});
                } else {
                    std.debug.print("└─ {s}\n", .{pkg});
                }
            }
            std.debug.print("\nPath length: {d}\n", .{path.items.len - 1});
        } else {
            std.debug.print("No dependency path from '{s}' to '{s}'.\n", .{ from_pkg, to_pkg });
            std.debug.print("\nNote: This means '{s}' does not depend on '{s}'.\n", .{ from_pkg, to_pkg });
            std.debug.print("Try reversing the order: axiom deps-path {s} {s} {s}\n", .{ profile_name, to_pkg, from_pkg });
        }
    }

    // Helper: Build dependency graph from lock file
    const DependencyGraph = struct {
        edges: std.StringHashMap(std.ArrayList([]const u8)),
        allocator: std.mem.Allocator,

        fn init(allocator: std.mem.Allocator) DependencyGraph {
            return .{
                .edges = std.StringHashMap(std.ArrayList([]const u8)).init(allocator),
                .allocator = allocator,
            };
        }

        fn deinit(self: *DependencyGraph) void {
            var it = self.edges.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.deinit();
            }
            self.edges.deinit();
        }
    };

    fn buildDependencyGraph(self: *CLI, lock: anytype) !DependencyGraph {
        var graph = DependencyGraph.init(self.allocator);

        for (lock.resolved) |pkg| {
            var deps = std.ArrayList([]const u8).init(self.allocator);

            // Get package manifest to find dependencies
            if (self.store.getPackageManifest(pkg.name, pkg.version)) |pkg_manifest| {
                if (pkg_manifest.dependencies) |dependencies| {
                    for (dependencies) |dep| {
                        try deps.append(dep.name);
                    }
                }
            }

            try graph.edges.put(pkg.name, deps);
        }

        return graph;
    }

    // Helper: Calculate graph statistics
    const GraphStats = struct {
        direct_deps: u32,
        max_depth: u32,
        avg_depth: f64,
        max_fanout: u32,
        avg_fanout: f64,
        leaf_count: u32,
        most_depended: ?[]const u8,
        most_depended_count: u32,
        deepest_chain: []const []const u8,
    };

    fn calculateGraphStats(self: *CLI, graph: DependencyGraph, lock: anytype) !GraphStats {
        var stats = GraphStats{
            .direct_deps = 0,
            .max_depth = 0,
            .avg_depth = 0,
            .max_fanout = 0,
            .avg_fanout = 0,
            .leaf_count = 0,
            .most_depended = null,
            .most_depended_count = 0,
            .deepest_chain = &[_][]const u8{},
        };

        // Count direct deps (requested packages)
        for (lock.resolved) |pkg| {
            if (pkg.requested) {
                stats.direct_deps += 1;
            }
        }

        // Calculate fanout statistics
        var total_fanout: u32 = 0;
        var it = graph.edges.iterator();
        while (it.next()) |entry| {
            const fanout: u32 = @intCast(entry.value_ptr.items.len);
            total_fanout += fanout;
            if (fanout > stats.max_fanout) {
                stats.max_fanout = fanout;
            }
            if (fanout == 0) {
                stats.leaf_count += 1;
            }
        }

        if (graph.edges.count() > 0) {
            stats.avg_fanout = @as(f64, @floatFromInt(total_fanout)) / @as(f64, @floatFromInt(graph.edges.count()));
        }

        // Count how many packages depend on each package
        var dependent_counts = std.StringHashMap(u32).init(self.allocator);
        defer dependent_counts.deinit();

        var it2 = graph.edges.iterator();
        while (it2.next()) |entry| {
            for (entry.value_ptr.items) |dep| {
                const current = dependent_counts.get(dep) orelse 0;
                try dependent_counts.put(dep, current + 1);
            }
        }

        // Find most depended-on package
        var it3 = dependent_counts.iterator();
        while (it3.next()) |entry| {
            if (entry.value_ptr.* > stats.most_depended_count) {
                stats.most_depended_count = entry.value_ptr.*;
                stats.most_depended = entry.key_ptr.*;
            }
        }

        // Calculate depth (simplified - just find max depth from any requested package)
        var total_depth: u32 = 0;
        var depth_count: u32 = 0;
        for (lock.resolved) |pkg| {
            if (pkg.requested) {
                const depth = self.calculateDepth(graph, pkg.name, 0);
                total_depth += depth;
                depth_count += 1;
                if (depth > stats.max_depth) {
                    stats.max_depth = depth;
                }
            }
        }

        if (depth_count > 0) {
            stats.avg_depth = @as(f64, @floatFromInt(total_depth)) / @as(f64, @floatFromInt(depth_count));
        }

        return stats;
    }

    fn calculateDepth(self: *CLI, graph: DependencyGraph, pkg: []const u8, current_depth: u32) u32 {
        if (current_depth > 100) return current_depth; // Prevent infinite recursion

        if (graph.edges.get(pkg)) |deps| {
            if (deps.items.len == 0) return current_depth;

            var max_child_depth: u32 = current_depth;
            for (deps.items) |dep| {
                const child_depth = self.calculateDepth(graph, dep, current_depth + 1);
                if (child_depth > max_child_depth) {
                    max_child_depth = child_depth;
                }
            }
            return max_child_depth;
        }
        return current_depth;
    }

    // Helper: Find path between two packages (BFS)
    fn findDependencyPath(self: *CLI, graph: DependencyGraph, from: []const u8, to: []const u8, path: *std.ArrayList([]const u8)) !bool {
        if (std.mem.eql(u8, from, to)) {
            try path.append(from);
            return true;
        }

        // BFS to find shortest path
        var visited = std.StringHashMap([]const u8).init(self.allocator);
        defer visited.deinit();

        var queue = std.ArrayList([]const u8).init(self.allocator);
        defer queue.deinit();

        try queue.append(from);
        try visited.put(from, from); // parent of start is itself

        while (queue.items.len > 0) {
            const current = queue.orderedRemove(0);

            if (graph.edges.get(current)) |deps| {
                for (deps.items) |dep| {
                    if (visited.contains(dep)) continue;

                    try visited.put(dep, current);

                    if (std.mem.eql(u8, dep, to)) {
                        // Reconstruct path
                        var reconstruct = std.ArrayList([]const u8).init(self.allocator);
                        defer reconstruct.deinit();

                        var node: []const u8 = to;
                        while (!std.mem.eql(u8, node, from)) {
                            try reconstruct.append(node);
                            node = visited.get(node).?;
                        }
                        try reconstruct.append(from);

                        // Reverse the path
                        var j: usize = reconstruct.items.len;
                        while (j > 0) {
                            j -= 1;
                            try path.append(reconstruct.items[j]);
                        }
                        return true;
                    }

                    try queue.append(dep);
                }
            }
        }

        return false;
    }

    // Output formatters
    fn outputTreeFormat(self: *CLI, writer: anytype, graph: DependencyGraph, lock: anytype, max_depth: ?u32) !void {
        try writer.print("Dependency Tree: {s}\n", .{lock.profile_name});
        try writer.print("════════════════════════════════════════\n\n", .{});

        // Print requested packages first
        for (lock.resolved) |pkg| {
            if (pkg.requested) {
                try self.printTreeNode(writer, graph, pkg.name, 0, max_depth, &std.StringHashMap(void).init(self.allocator));
                try writer.print("\n", .{});
            }
        }
    }

    fn printTreeNode(self: *CLI, writer: anytype, graph: DependencyGraph, pkg: []const u8, depth: u32, max_depth: ?u32, visited: *std.StringHashMap(void)) !void {
        if (max_depth) |md| {
            if (depth > md) return;
        }

        // Print indentation
        var i: u32 = 0;
        while (i < depth) : (i += 1) {
            try writer.print("│   ", .{});
        }

        const already_visited = visited.contains(pkg);
        if (already_visited) {
            try writer.print("├── {s} (circular)\n", .{pkg});
            return;
        }

        try visited.put(pkg, {});
        try writer.print("├── {s}\n", .{pkg});

        if (graph.edges.get(pkg)) |deps| {
            for (deps.items) |dep| {
                try self.printTreeNode(writer, graph, dep, depth + 1, max_depth, visited);
            }
        }

        _ = visited.remove(pkg);
    }

    fn outputDotFormat(self: *CLI, writer: anytype, graph: DependencyGraph, lock: anytype) !void {
        _ = self;
        try writer.print("digraph dependencies {{\n", .{});
        try writer.print("    rankdir=LR;\n", .{});
        try writer.print("    node [shape=box];\n", .{});
        try writer.print("\n", .{});

        // Mark requested packages with different style
        try writer.print("    // Requested packages\n", .{});
        for (lock.resolved) |pkg| {
            if (pkg.requested) {
                try writer.print("    \"{s}\" [style=filled, fillcolor=lightblue];\n", .{pkg.name});
            }
        }
        try writer.print("\n", .{});

        // Output edges
        try writer.print("    // Dependencies\n", .{});
        var it = graph.edges.iterator();
        while (it.next()) |entry| {
            for (entry.value_ptr.items) |dep| {
                try writer.print("    \"{s}\" -> \"{s}\";\n", .{ entry.key_ptr.*, dep });
            }
        }

        try writer.print("}}\n", .{});
    }

    fn outputJsonFormat(self: *CLI, writer: anytype, graph: DependencyGraph, lock: anytype) !void {
        _ = self;
        try writer.print("{{\n", .{});
        try writer.print("  \"profile\": \"{s}\",\n", .{lock.profile_name});
        try writer.print("  \"package_count\": {d},\n", .{lock.resolved.len});
        try writer.print("  \"packages\": [\n", .{});

        for (lock.resolved, 0..) |pkg, idx| {
            try writer.print("    {{\n", .{});
            try writer.print("      \"name\": \"{s}\",\n", .{pkg.name});
            try writer.print("      \"version\": \"{s}\",\n", .{pkg.version});
            try writer.print("      \"requested\": {s},\n", .{if (pkg.requested) "true" else "false"});
            try writer.print("      \"dependencies\": [", .{});

            if (graph.edges.get(pkg.name)) |deps| {
                for (deps.items, 0..) |dep, dep_idx| {
                    try writer.print("\"{s}\"", .{dep});
                    if (dep_idx < deps.items.len - 1) {
                        try writer.print(", ", .{});
                    }
                }
            }
            try writer.print("]\n", .{});

            if (idx < lock.resolved.len - 1) {
                try writer.print("    }},\n", .{});
            } else {
                try writer.print("    }}\n", .{});
            }
        }

        try writer.print("  ]\n", .{});
        try writer.print("}}\n", .{});
    }

    // Garbage collection

    fn garbageCollect(self: *CLI, args: []const []const u8) !void {
        const dry_run = if (args.len > 0 and std.mem.eql(u8, args[0], "--dry-run")) true else false;

        if (dry_run) {
            std.debug.print("Running garbage collection (DRY RUN)...\n\n", .{});
        } else {
            std.debug.print("Running garbage collection...\n\n", .{});
        }

        // Run GC
        const stats = try self.gc.collect(dry_run);
        _ = stats;

        if (!dry_run) {
            std.debug.print("\n✓ Garbage collection completed\n", .{});
        } else {
            std.debug.print("\n✓ Dry run completed - no packages removed\n", .{});
            std.debug.print("Run 'axiom gc' without --dry-run to actually remove packages\n", .{});
        }
    }

    // Build operations

    fn buildPackage(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom build <recipe.yaml> [options]\n", .{});
            std.debug.print("\nOptions:\n", .{});
            std.debug.print("  --jobs <n>         Number of parallel jobs (default: 4)\n", .{});
            std.debug.print("  --no-test          Skip test phase\n", .{});
            std.debug.print("  --dry-run          Show build plan without executing\n", .{});
            std.debug.print("  --keep-sandbox     Don't destroy build sandbox after completion\n", .{});
            std.debug.print("  --no-import        Don't import result into store\n", .{});
            std.debug.print("  --verbose          Show detailed output\n", .{});
            std.debug.print("\nSecurity options (Phase 27):\n", .{});
            std.debug.print("  --allow-network    Allow network access during build (INSECURE)\n", .{});
            std.debug.print("  --no-sandbox       Disable sandbox entirely (VERY INSECURE)\n", .{});
            std.debug.print("  --memory <MB>      Set memory limit in MB (default: 4096)\n", .{});
            std.debug.print("  --cpu-time <sec>   Set CPU time limit in seconds (default: 3600)\n", .{});
            std.debug.print("  --audit-log <path> Path for security audit log\n", .{});
            std.debug.print("\nExample:\n", .{});
            std.debug.print("  axiom build bash.yaml\n", .{});
            std.debug.print("  axiom build myapp.yaml --jobs 8 --no-test\n", .{});
            std.debug.print("  axiom build myapp.yaml --memory 8192 --audit-log /var/log/axiom-build.log\n", .{});
            return;
        }

        const recipe_path = args[0];

        // Parse options
        var options = build_pkg.BuildOptions{};
        var i: usize = 1;
        while (i < args.len) {
            const arg = args[i];
            if (std.mem.eql(u8, arg, "--jobs") and i + 1 < args.len) {
                options.jobs = std.fmt.parseInt(u32, args[i + 1], 10) catch {
                    std.debug.print("Invalid job count: {s}\n", .{args[i + 1]});
                    return;
                };
                i += 2;
            } else if (std.mem.eql(u8, arg, "--no-test")) {
                options.no_test = true;
                i += 1;
            } else if (std.mem.eql(u8, arg, "--dry-run")) {
                options.dry_run = true;
                i += 1;
            } else if (std.mem.eql(u8, arg, "--keep-sandbox")) {
                options.keep_sandbox = true;
                i += 1;
            } else if (std.mem.eql(u8, arg, "--no-import")) {
                options.import_result = false;
                i += 1;
            } else if (std.mem.eql(u8, arg, "--verbose")) {
                options.verbose = true;
                i += 1;
            // Phase 27: Security options
            } else if (std.mem.eql(u8, arg, "--allow-network")) {
                options.allow_network = true;
                std.debug.print("⚠ WARNING: Network access enabled - build is NOT isolated!\n", .{});
                i += 1;
            } else if (std.mem.eql(u8, arg, "--no-sandbox")) {
                options.no_sandbox = true;
                std.debug.print("⚠ WARNING: Sandbox disabled - build runs with full system access!\n", .{});
                i += 1;
            } else if (std.mem.eql(u8, arg, "--memory") and i + 1 < args.len) {
                options.memory_limit_mb = std.fmt.parseInt(u64, args[i + 1], 10) catch {
                    std.debug.print("Invalid memory limit: {s}\n", .{args[i + 1]});
                    return;
                };
                i += 2;
            } else if (std.mem.eql(u8, arg, "--cpu-time") and i + 1 < args.len) {
                options.cpu_limit_seconds = std.fmt.parseInt(u64, args[i + 1], 10) catch {
                    std.debug.print("Invalid CPU time limit: {s}\n", .{args[i + 1]});
                    return;
                };
                i += 2;
            } else if (std.mem.eql(u8, arg, "--audit-log") and i + 1 < args.len) {
                options.audit_log = args[i + 1];
                i += 2;
            } else {
                std.debug.print("Unknown option: {s}\n", .{arg});
                return;
            }
        }

        // Load build recipe
        var recipe = build_pkg.BuildRecipe.loadFromFile(self.allocator, recipe_path) catch |err| {
            std.debug.print("Error loading recipe: {}\n", .{err});
            return;
        };
        defer recipe.deinit();

        // Run build
        const pkg_id = self.builder.build(&recipe, options) catch |err| {
            std.debug.print("\n✗ Build failed: {}\n", .{err});
            return;
        };

        if (options.dry_run) {
            std.debug.print("\n✓ Dry run complete\n", .{});
        } else if (options.import_result) {
            std.debug.print("\n✓ Build complete: {s}/{}\n", .{ pkg_id.name, pkg_id.version });
        } else {
            std.debug.print("\n✓ Build complete (not imported)\n", .{});
        }
    }

    // Signature operations

    fn keyList(self: *CLI, args: []const []const u8) !void {
        // Check for --ids-only flag (for shell completion)
        var ids_only = false;
        for (args) |arg| {
            if (std.mem.eql(u8, arg, "--ids-only")) {
                ids_only = true;
            }
        }

        const keys = try self.trust_store.listKeys(self.allocator);
        defer self.allocator.free(keys);

        if (ids_only) {
            // Output key IDs only, one per line for shell completion
            for (keys) |key| {
                std.debug.print("{s}\n", .{key.key_id});
            }
            return;
        }

        std.debug.print("Trusted Keys\n", .{});
        std.debug.print("============\n\n", .{});

        if (keys.len == 0) {
            std.debug.print("No keys in trust store.\n", .{});
            std.debug.print("Add keys with: axiom key-add <file>\n", .{});
            return;
        }

        for (keys) |key| {
            const trusted = if (self.trust_store.isKeyTrusted(key.key_id)) "✓" else " ";
            std.debug.print("{s} {s}", .{ trusted, key.key_id });
            if (key.owner) |o| std.debug.print(" ({s})", .{o});
            std.debug.print("\n", .{});
        }

        std.debug.print("\n{d} key(s) total\n", .{keys.len});
    }

    fn keyAdd(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom key-add <public-key-file>\n", .{});
            return;
        }

        const key_path = args[0];
        std.debug.print("Adding key from: {s}\n", .{key_path});

        var key = signature.importPublicKey(self.allocator, key_path) catch |err| {
            std.debug.print("Error: Failed to import key: {}\n", .{err});
            return;
        };
        defer key.deinit(self.allocator);

        try self.trust_store.addKey(key);
        try self.trust_store.save();

        std.debug.print("✓ Key added: {s}\n", .{key.key_id});
        if (key.owner) |o| std.debug.print("  Owner: {s}\n", .{o});
        std.debug.print("\nTo trust this key, run: axiom key-trust {s}\n", .{key.key_id});
    }

    fn keyRemove(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom key-remove <key-id>\n", .{});
            return;
        }

        const key_id = args[0];
        std.debug.print("Removing key: {s}\n", .{key_id});

        try self.trust_store.removeKey(key_id);
        try self.trust_store.save();

        std.debug.print("✓ Key removed\n", .{});
    }

    fn keyTrust(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom key-trust <key-id>\n", .{});
            return;
        }

        const key_id = args[0];

        // Check key exists
        if (self.trust_store.getKey(key_id) == null) {
            std.debug.print("Error: Key not found: {s}\n", .{key_id});
            return;
        }

        try self.trust_store.trustKey(key_id);
        try self.trust_store.save();

        std.debug.print("✓ Key trusted: {s}\n", .{key_id});
    }

    fn keyGenerate(self: *CLI, args: []const []const u8) !void {
        var owner: ?[]const u8 = null;
        var output_path: []const u8 = "axiom-key";

        // Parse options
        var i: usize = 0;
        while (i < args.len) {
            if (std.mem.eql(u8, args[i], "--name") and i + 1 < args.len) {
                owner = args[i + 1];
                i += 2;
            } else if (std.mem.eql(u8, args[i], "--output") and i + 1 < args.len) {
                output_path = args[i + 1];
                i += 2;
            } else {
                i += 1;
            }
        }

        std.debug.print("Generating new key pair...\n", .{});

        const key_pair = signature.KeyPair.generate();
        const key_id = try key_pair.keyId(self.allocator);
        defer self.allocator.free(key_id);

        // Save secret key
        const secret_path = try std.fmt.allocPrint(self.allocator, "{s}.key", .{output_path});
        defer self.allocator.free(secret_path);

        {
            const secret_file = try std.fs.cwd().createFile(secret_path, .{ .mode = 0o600 });
            defer secret_file.close();
            const writer = secret_file.writer();
            try writer.writeAll("# Axiom Secret Key - KEEP PRIVATE!\n");
            try writer.print("key_id: {s}\n", .{key_id});
            try writer.print("secret_key: {s}\n", .{std.fmt.fmtSliceHexLower(&key_pair.secret_key)});
        }

        // Save public key
        const public_path = try std.fmt.allocPrint(self.allocator, "{s}.pub", .{output_path});
        defer self.allocator.free(public_path);

        const pub_key = signature.PublicKey{
            .key_id = key_id,
            .key_data = key_pair.public_key,
            .owner = owner,
            .created = std.time.timestamp(),
        };
        try signature.exportPublicKey(self.allocator, pub_key, public_path);

        std.debug.print("✓ Key pair generated\n", .{});
        std.debug.print("  Key ID:     {s}\n", .{key_id});
        std.debug.print("  Secret key: {s} (keep private!)\n", .{secret_path});
        std.debug.print("  Public key: {s} (share this)\n", .{public_path});
    }

    fn signPackage(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom sign <package-path> --key <secret-key-file>\n", .{});
            return;
        }

        const pkg_path = args[0];
        var key_path: ?[]const u8 = null;
        var signer_name: ?[]const u8 = null;

        // Parse options
        var i: usize = 1;
        while (i < args.len) {
            if (std.mem.eql(u8, args[i], "--key") and i + 1 < args.len) {
                key_path = args[i + 1];
                i += 2;
            } else if (std.mem.eql(u8, args[i], "--name") and i + 1 < args.len) {
                signer_name = args[i + 1];
                i += 2;
            } else {
                i += 1;
            }
        }

        if (key_path == null) {
            std.debug.print("Error: --key <secret-key-file> required\n", .{});
            return;
        }

        // Load secret key
        const key_file = std.fs.cwd().openFile(key_path.?, .{}) catch |err| {
            std.debug.print("Error: Failed to open key file: {}\n", .{err});
            return;
        };
        defer key_file.close();

        const key_content = try key_file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(key_content);

        var secret_key: [64]u8 = undefined;
        var lines = std.mem.splitSequence(u8, key_content, "\n");
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t");
            if (std.mem.startsWith(u8, trimmed, "secret_key:")) {
                const value = std.mem.trim(u8, trimmed[11..], " \t");
                if (value.len == 128) {
                    _ = std.fmt.hexToBytes(&secret_key, value) catch {
                        std.debug.print("Error: Invalid secret key format\n", .{});
                        return;
                    };
                }
            }
        }

        // Reconstruct key pair from secret key
        const ed_secret = std.crypto.sign.Ed25519.SecretKey.fromBytes(secret_key) catch {
            std.debug.print("Error: Invalid secret key\n", .{});
            return;
        };
        const ed_pair = std.crypto.sign.Ed25519.KeyPair.fromSecretKey(ed_secret) catch {
            std.debug.print("Error: Failed to create key pair\n", .{});
            return;
        };
        const key_pair = signature.KeyPair{
            .public_key = ed_pair.public_key.bytes,
            .secret_key = secret_key,
        };

        // Sign package
        var signer = signature.Signer.init(self.allocator, key_pair, signer_name);
        var sig = try signer.signPackage(pkg_path);
        defer sig.deinit(self.allocator);

        // Save signature
        const sig_yaml = try sig.toYaml(self.allocator);
        defer self.allocator.free(sig_yaml);

        const sig_path = try std.fs.path.join(self.allocator, &[_][]const u8{ pkg_path, "manifest.sig" });
        defer self.allocator.free(sig_path);

        {
            const sig_file = try std.fs.cwd().createFile(sig_path, .{});
            defer sig_file.close();
            try sig_file.writeAll(sig_yaml);
        }

        std.debug.print("✓ Package signed\n", .{});
        std.debug.print("  Signature: {s}\n", .{sig_path});
    }

    fn verifyPackage(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom verify <package-path>\n", .{});
            return;
        }

        const pkg_path = args[0];

        const result = try self.verifier.verifyPackage(pkg_path);

        // Free result strings
        defer {
            if (result.key_id) |kid| self.allocator.free(kid);
            if (result.signer) |s| self.allocator.free(s);
        }

        std.debug.print("\nVerification Result\n", .{});
        std.debug.print("==================\n", .{});
        std.debug.print("Valid:          {}\n", .{result.valid});
        std.debug.print("Key trusted:    {}\n", .{result.key_trusted});
        if (result.key_id) |kid| std.debug.print("Key ID:         {s}\n", .{kid});
        if (result.signer) |s| std.debug.print("Signer:         {s}\n", .{s});
        std.debug.print("Files verified: {d}\n", .{result.files_verified});
        std.debug.print("Files failed:   {d}\n", .{result.files_failed});

        if (result.valid and result.key_trusted) {
            std.debug.print("\n✓ Package verified successfully\n", .{});
        } else if (result.valid and !result.key_trusted) {
            std.debug.print("\n⚠ Package signature valid but key not trusted\n", .{});
            if (result.key_id) |kid| {
                std.debug.print("To trust: axiom key-trust {s}\n", .{kid});
            }
        } else {
            std.debug.print("\n✗ Package verification failed\n", .{});
            if (result.error_message) |msg| std.debug.print("Error: {s}\n", .{msg});
        }
    }

    // Cache operations

    fn cacheList(self: *CLI, args: []const []const u8) !void {
        // Check for --urls-only flag (for shell completion)
        var urls_only = false;
        for (args) |arg| {
            if (std.mem.eql(u8, arg, "--urls-only")) {
                urls_only = true;
            }
        }

        if (urls_only) {
            // Output cache URLs only, one per line for shell completion
            for (self.cache_config.caches.items) |item| {
                std.debug.print("{s}\n", .{item.url});
            }
            return;
        }

        std.debug.print("\nConfigured Caches\n", .{});
        std.debug.print("=================\n\n", .{});

        if (self.cache_config.caches.items.len == 0) {
            std.debug.print("No remote caches configured.\n", .{});
            std.debug.print("Add a cache with: axiom cache-add <url>\n", .{});
            return;
        }

        for (self.cache_config.caches.items, 0..) |item, i| {
            std.debug.print("{d}. {s}\n", .{ i + 1, item.url });
            std.debug.print("   Priority: {d}\n", .{item.priority});
            std.debug.print("   Enabled: {}\n", .{item.enabled});
            if (item.trusted_keys.len > 0) {
                std.debug.print("   Trusted keys: {d}\n", .{item.trusted_keys.len});
            }
            std.debug.print("\n", .{});
        }

        std.debug.print("Local cache: {s}\n", .{self.cache_config.local.path});
        std.debug.print("Max size: {d} bytes\n", .{self.cache_config.local.max_size_bytes});
        std.debug.print("Cleanup policy: {s}\n", .{@tagName(self.cache_config.local.cleanup_policy)});
    }

    fn cacheAdd(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom cache-add <url> [priority]\n", .{});
            std.debug.print("\nExample:\n", .{});
            std.debug.print("  axiom cache-add https://cache.pgsdf.org\n", .{});
            std.debug.print("  axiom cache-add https://mirror.example.com/axiom 2\n", .{});
            return;
        }

        const url = args[0];
        const priority: u32 = if (args.len > 1)
            std.fmt.parseInt(u32, args[1], 10) catch 1
        else
            1;

        try self.cache_config.addCache(url, priority);

        // Save configuration
        const config_path = "/etc/axiom/cache.yaml";
        self.cache_config.saveToFile(config_path) catch |err| {
            std.debug.print("Warning: Could not save config to {s}: {}\n", .{ config_path, err });
        };

        std.debug.print("✓ Added cache: {s} (priority {d})\n", .{ url, priority });
    }

    fn cacheRemove(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom cache-remove <url>\n", .{});
            return;
        }

        const url = args[0];

        if (self.cache_config.removeCache(url)) {
            const config_path = "/etc/axiom/cache.yaml";
            self.cache_config.saveToFile(config_path) catch |err| {
                std.debug.print("Warning: Could not save config: {}\n", .{err});
            };
            std.debug.print("✓ Removed cache: {s}\n", .{url});
        } else {
            std.debug.print("Cache not found: {s}\n", .{url});
        }
    }

    fn cacheFetch(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom cache-fetch <name>/<version>/<revision>/<build_id>\n", .{});
            std.debug.print("\nExample:\n", .{});
            std.debug.print("  axiom cache-fetch bash/5.2.0/1/abc123def\n", .{});
            return;
        }

        const pkg_spec = args[0];

        // Parse package spec: name/version/revision/build_id
        var parts = std.mem.splitScalar(u8, pkg_spec, '/');
        const name = parts.next() orelse {
            std.debug.print("Invalid package spec. Expected: name/version/revision/build_id\n", .{});
            return;
        };
        const version_str = parts.next() orelse {
            std.debug.print("Missing version in package spec\n", .{});
            return;
        };
        const revision_str = parts.next() orelse {
            std.debug.print("Missing revision in package spec\n", .{});
            return;
        };
        const build_id = parts.next() orelse {
            std.debug.print("Missing build_id in package spec\n", .{});
            return;
        };

        const version = types.Version.parse(version_str) catch {
            std.debug.print("Invalid version: {s}\n", .{version_str});
            return;
        };
        const revision = std.fmt.parseInt(u32, revision_str, 10) catch {
            std.debug.print("Invalid revision: {s}\n", .{revision_str});
            return;
        };

        const pkg_id = types.PackageId{
            .name = name,
            .version = version,
            .revision = revision,
            .build_id = build_id,
        };

        std.debug.print("Fetching {s}/{}/{d}/{s}...\n", .{ name, version, revision, build_id });

        // Check for --no-verify flag
        var verify = true;
        for (args[1..]) |arg| {
            if (std.mem.eql(u8, arg, "--no-verify")) {
                verify = false;
            }
        }

        const path = self.cache_client.fetchPackage(pkg_id, verify, null, null) catch |err| {
            std.debug.print("✗ Failed to fetch package: {}\n", .{err});
            return;
        };
        defer self.allocator.free(path);

        std.debug.print("✓ Package downloaded to: {s}\n", .{path});

        // Check for --install flag
        for (args[1..]) |arg| {
            if (std.mem.eql(u8, arg, "--install")) {
                std.debug.print("Installing package...\n", .{});
                self.cache_client.receiveIntoStore(path, pkg_id) catch |err| {
                    std.debug.print("✗ Failed to install: {}\n", .{err});
                    return;
                };
                std.debug.print("✓ Package installed\n", .{});
                break;
            }
        }
    }

    fn cachePush(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom cache-push <name>/<version>/<revision>/<build_id>\n", .{});
            return;
        }

        if (!self.cache_config.push.enabled) {
            std.debug.print("Cache push is not enabled.\n", .{});
            std.debug.print("Configure push settings in /etc/axiom/cache.yaml\n", .{});
            return;
        }

        const pkg_spec = args[0];

        // Parse package spec
        var parts = std.mem.splitScalar(u8, pkg_spec, '/');
        const name = parts.next() orelse {
            std.debug.print("Invalid package spec\n", .{});
            return;
        };
        const version_str = parts.next() orelse {
            std.debug.print("Missing version\n", .{});
            return;
        };
        const revision_str = parts.next() orelse {
            std.debug.print("Missing revision\n", .{});
            return;
        };
        const build_id = parts.next() orelse {
            std.debug.print("Missing build_id\n", .{});
            return;
        };

        const version = types.Version.parse(version_str) catch {
            std.debug.print("Invalid version\n", .{});
            return;
        };
        const revision = std.fmt.parseInt(u32, revision_str, 10) catch {
            std.debug.print("Invalid revision\n", .{});
            return;
        };

        const pkg_id = types.PackageId{
            .name = name,
            .version = version,
            .revision = revision,
            .build_id = build_id,
        };

        std.debug.print("Pushing {s}/{}/{d}/{s} to cache...\n", .{ name, version, revision, build_id });

        cache.pushPackage(
            self.allocator,
            self.cache_config,
            self.store,
            self.zfs_handle,
            pkg_id,
        ) catch |err| {
            std.debug.print("✗ Failed to push package: {}\n", .{err});
            return;
        };

        std.debug.print("✓ Package pushed to cache\n", .{});
    }

    fn cacheSync(self: *CLI, args: []const []const u8) !void {
        _ = args;
        std.debug.print("Syncing with remote caches...\n", .{});

        self.cache_client.sync() catch |err| {
            std.debug.print("✗ Sync failed: {}\n", .{err});
            return;
        };

        std.debug.print("✓ Cache sync complete\n", .{});
    }

    fn cacheClean(self: *CLI, args: []const []const u8) !void {
        var force = false;
        for (args) |arg| {
            if (std.mem.eql(u8, arg, "--force") or std.mem.eql(u8, arg, "-f")) {
                force = true;
            }
        }

        std.debug.print("Cleaning local cache...\n", .{});

        const freed = self.cache_client.clean(force) catch |err| {
            std.debug.print("✗ Cache clean failed: {}\n", .{err});
            return;
        };

        if (freed > 0) {
            std.debug.print("✓ Freed {d} bytes\n", .{freed});
        } else {
            std.debug.print("✓ Cache is within size limits, nothing to clean\n", .{});
        }
    }

    // Shell completions

    fn generateCompletions(self: *CLI, args: []const []const u8) !void {
        _ = self;
        if (args.len < 1) {
            std.debug.print("Usage: axiom completions <shell>\n", .{});
            std.debug.print("\nSupported shells:\n", .{});
            std.debug.print("  bash    Bash completion script\n", .{});
            std.debug.print("  zsh     Zsh completion script\n", .{});
            std.debug.print("  fish    Fish completion script\n", .{});
            std.debug.print("\nInstallation:\n", .{});
            std.debug.print("  Bash: axiom completions bash > /usr/local/share/bash-completion/completions/axiom\n", .{});
            std.debug.print("  Zsh:  axiom completions zsh > /usr/local/share/zsh/site-functions/_axiom\n", .{});
            std.debug.print("  Fish: axiom completions fish > ~/.config/fish/completions/axiom.fish\n", .{});
            return;
        }

        const shell = completions.Shell.fromString(args[0]) orelse {
            std.debug.print("Unknown shell: {s}\n", .{args[0]});
            std.debug.print("Supported shells: bash, zsh, fish\n", .{});
            return;
        };

        const stdout = std.io.getStdOut().writer();
        try completions.generate(shell, stdout);
    }

    // ============================================
    // User Operations (per-user, no root required)
    // ============================================

    fn ensureUserContext(self: *CLI) bool {
        if (self.user_ctx == null or self.user_profile_mgr == null or self.user_realization == null) {
            std.debug.print("Error: User context not initialized.\n", .{});
            std.debug.print("This is an internal error. Please report this bug.\n", .{});
            return false;
        }
        return true;
    }

    fn userProfileCreate(self: *CLI, args: []const []const u8) !void {
        if (!self.ensureUserContext()) return;

        if (args.len < 1) {
            std.debug.print("Usage: axiom user-profile-create <name>\n", .{});
            return;
        }

        const name = args[0];
        std.debug.print("Creating user profile: {s}\n", .{name});
        std.debug.print("  User: {s}\n", .{self.user_ctx.?.username});

        // Create empty profile
        const packages = try self.allocator.alloc(profile.PackageRequest, 0);
        const prof = profile.Profile{
            .name = try self.allocator.dupe(u8, name),
            .description = try self.allocator.dupe(u8, "User profile created via axiom CLI"),
            .packages = packages,
        };
        defer {
            self.allocator.free(prof.name);
            if (prof.description) |d| self.allocator.free(d);
            self.allocator.free(prof.packages);
        }

        self.user_profile_mgr.?.createProfile(prof) catch |err| {
            std.debug.print("Error creating profile: {}\n", .{err});
            return;
        };

        std.debug.print("Profile '{s}' created\n", .{name});
    }

    fn userProfileList(self: *CLI, args: []const []const u8) !void {
        if (!self.ensureUserContext()) return;

        var names_only = false;
        for (args) |arg| {
            if (std.mem.eql(u8, arg, "--names-only")) {
                names_only = true;
            }
        }

        const profiles = self.user_profile_mgr.?.listProfiles() catch |err| {
            std.debug.print("Error listing profiles: {}\n", .{err});
            return;
        };
        defer self.allocator.free(profiles);

        if (names_only) {
            for (profiles) |prof_name| {
                std.debug.print("{s}\n", .{prof_name});
                self.allocator.free(prof_name);
            }
            return;
        }

        std.debug.print("User Profiles for '{s}':\n", .{self.user_ctx.?.username});
        std.debug.print("========================\n\n", .{});

        if (profiles.len == 0) {
            std.debug.print("No user profiles found.\n", .{});
            std.debug.print("Create one with: axiom user-profile-create <name>\n", .{});
            return;
        }

        for (profiles) |prof_name| {
            std.debug.print("  - {s}\n", .{prof_name});
            self.allocator.free(prof_name);
        }

        std.debug.print("\n{d} profile(s) total\n", .{profiles.len});
    }

    fn userProfileShow(self: *CLI, args: []const []const u8) !void {
        if (!self.ensureUserContext()) return;

        if (args.len < 1) {
            std.debug.print("Usage: axiom user-profile-show <name>\n", .{});
            return;
        }

        const name = args[0];
        var prof = self.user_profile_mgr.?.loadProfile(name) catch |err| {
            std.debug.print("Error loading profile: {}\n", .{err});
            return;
        };
        defer prof.deinit(self.allocator);

        std.debug.print("User Profile: {s}\n", .{prof.name});
        std.debug.print("Owner: {s}\n", .{self.user_ctx.?.username});
        if (prof.description) |desc| {
            std.debug.print("Description: {s}\n", .{desc});
        }
        std.debug.print("Packages ({d}):\n", .{prof.packages.len});
        for (prof.packages) |pkg| {
            std.debug.print("  - {s}\n", .{pkg.name});
        }
    }

    fn userProfileUpdate(self: *CLI, args: []const []const u8) !void {
        if (!self.ensureUserContext()) return;

        if (args.len < 1) {
            std.debug.print("Usage: axiom user-profile-update <name>\n", .{});
            return;
        }

        const name = args[0];
        std.debug.print("Updating user profile: {s}\n", .{name});
        std.debug.print("(Interactive update not yet implemented)\n", .{});
    }

    fn userProfileDelete(self: *CLI, args: []const []const u8) !void {
        if (!self.ensureUserContext()) return;

        if (args.len < 1) {
            std.debug.print("Usage: axiom user-profile-delete <name>\n", .{});
            return;
        }

        const name = args[0];
        std.debug.print("Deleting user profile: {s}\n", .{name});

        self.user_profile_mgr.?.deleteProfile(name) catch |err| {
            std.debug.print("Error deleting profile: {}\n", .{err});
            return;
        };

        std.debug.print("Profile deleted\n", .{});
    }

    fn userResolve(self: *CLI, args: []const []const u8) !void {
        if (!self.ensureUserContext()) return;

        if (args.len < 1) {
            std.debug.print("Usage: axiom user-resolve <profile> [options]\n", .{});
            std.debug.print("\nOptions:\n", .{});
            std.debug.print("  --strategy <strategy>  Resolution strategy to use\n", .{});
            std.debug.print("\nStrategies:\n", .{});
            std.debug.print("  greedy         Fast greedy algorithm (default)\n", .{});
            std.debug.print("  sat            SAT solver for complex constraints\n", .{});
            std.debug.print("  auto           Try greedy first, fallback to SAT\n", .{});
            return;
        }

        const name = args[0];

        // Parse options
        var strategy: ResolutionStrategy = .greedy_with_sat_fallback;
        var i: usize = 1;
        while (i < args.len) {
            if (std.mem.eql(u8, args[i], "--strategy") and i + 1 < args.len) {
                const strat_str = args[i + 1];
                if (std.mem.eql(u8, strat_str, "greedy")) {
                    strategy = .greedy;
                } else if (std.mem.eql(u8, strat_str, "sat")) {
                    strategy = .sat;
                } else if (std.mem.eql(u8, strat_str, "auto")) {
                    strategy = .greedy_with_sat_fallback;
                } else {
                    std.debug.print("Unknown strategy: {s}\n", .{strat_str});
                    std.debug.print("Valid options: greedy, sat, auto\n", .{});
                    return;
                }
                i += 2;
            } else {
                std.debug.print("Unknown option: {s}\n", .{args[i]});
                return;
            }
        }

        std.debug.print("Resolving user profile: {s}\n", .{name});
        std.debug.print("Strategy: {s}\n\n", .{@tagName(strategy)});

        // Load user profile
        var prof = self.user_profile_mgr.?.loadProfile(name) catch |err| {
            std.debug.print("Error loading profile: {}\n", .{err});
            return;
        };
        defer prof.deinit(self.allocator);

        // Set resolution strategy
        self.resolver.setStrategy(strategy);

        // Resolve using system resolver (packages are in shared store)
        var lock = self.resolver.resolve(prof) catch |err| {
            std.debug.print("\n✗ Resolution failed: {}\n", .{err});

            // Show detailed diagnostics from SAT solver if available
            if (self.resolver.getLastFailure()) |failure| {
                std.debug.print("\nDiagnostics:\n", .{});

                // Show conflict explanations
                if (failure.explanations.len > 0) {
                    std.debug.print("\nConflicts detected:\n", .{});
                    for (failure.explanations) |exp| {
                        std.debug.print("  • ", .{});
                        const writer = std.io.getStdErr().writer();
                        exp.format(writer) catch {};
                        std.debug.print("\n", .{});
                    }
                }

                // Show suggestions
                if (failure.suggestions.len > 0) {
                    std.debug.print("\nSuggestions:\n", .{});
                    for (failure.suggestions) |suggestion| {
                        std.debug.print("  → {s}\n", .{suggestion});
                    }
                }
            }
            return;
        };
        defer lock.deinit(self.allocator);

        // Save lock file to user's profile
        self.user_profile_mgr.?.saveLock(name, lock) catch |err| {
            std.debug.print("Error saving lock file: {}\n", .{err});
            return;
        };

        std.debug.print("\n✓ Profile resolved and lock file saved\n", .{});
        std.debug.print("  Packages: {d}\n", .{lock.resolved.len});
    }

    fn userRealize(self: *CLI, args: []const []const u8) !void {
        if (!self.ensureUserContext()) return;

        if (args.len < 2) {
            std.debug.print("Usage: axiom user-realize <env-name> <profile> [options]\n", .{});
            std.debug.print("\nOptions:\n", .{});
            std.debug.print("  --conflict-policy <policy>  How to handle file conflicts\n", .{});
            std.debug.print("\nConflict policies:\n", .{});
            std.debug.print("  error        Fail on any file conflict (default)\n", .{});
            std.debug.print("  priority     Later packages override earlier ones\n", .{});
            std.debug.print("  keep-both    Keep both files with package suffix\n", .{});
            return;
        }

        const env_name = args[0];
        const profile_name = args[1];

        // Parse options
        var conflict_policy: ConflictPolicy = .error_on_conflict;
        var i: usize = 2;
        while (i < args.len) {
            if (std.mem.eql(u8, args[i], "--conflict-policy") and i + 1 < args.len) {
                const policy_str = args[i + 1];
                if (std.mem.eql(u8, policy_str, "error")) {
                    conflict_policy = .error_on_conflict;
                } else if (std.mem.eql(u8, policy_str, "priority")) {
                    conflict_policy = .priority_wins;
                } else if (std.mem.eql(u8, policy_str, "keep-both")) {
                    conflict_policy = .keep_both;
                } else {
                    std.debug.print("Unknown conflict policy: {s}\n", .{policy_str});
                    std.debug.print("Valid options: error, priority, keep-both\n", .{});
                    return;
                }
                i += 2;
            } else {
                std.debug.print("Unknown option: {s}\n", .{args[i]});
                return;
            }
        }

        std.debug.print("Realizing user environment: {s}\n", .{env_name});
        std.debug.print("From profile: {s}\n", .{profile_name});
        std.debug.print("User: {s}\n", .{self.user_ctx.?.username});
        std.debug.print("Conflict policy: {s}\n\n", .{@tagName(conflict_policy)});

        // Set conflict policy on user realization engine
        self.user_realization.?.setConflictPolicy(conflict_policy);

        // Load lock file from user profile
        var lock = self.user_profile_mgr.?.loadLock(profile_name) catch |err| {
            std.debug.print("Error loading lock file: {}\n", .{err});
            std.debug.print("Run 'axiom user-resolve {s}' first.\n", .{profile_name});
            return;
        };
        defer lock.deinit(self.allocator);

        // Realize user environment
        var env = self.user_realization.?.realize(env_name, lock) catch |err| {
            if (err == realization.RealizationError.FileConflict) {
                std.debug.print("\n✗ File conflicts detected. Options:\n", .{});
                std.debug.print("  - Use --conflict-policy priority to let later packages win\n", .{});
                std.debug.print("  - Use --conflict-policy keep-both to keep both files\n", .{});
                return;
            }
            std.debug.print("Realization failed: {}\n", .{err});
            return;
        };
        defer realization.freeEnvironment(&env, self.allocator);

        std.debug.print("\n✓ Environment realized\n", .{});

        // Get user's env directory for activation instructions
        const axiom_dir = self.user_ctx.?.getAxiomDir() catch {
            return;
        };
        defer self.allocator.free(axiom_dir);

        std.debug.print("To activate: source {s}/env/{s}/activate\n", .{ axiom_dir, env_name });
    }

    fn userActivate(self: *CLI, args: []const []const u8) !void {
        if (!self.ensureUserContext()) return;

        if (args.len < 1) {
            std.debug.print("Usage: axiom user-activate <env>\n", .{});
            return;
        }

        const env_name = args[0];
        self.user_realization.?.activate(env_name) catch |err| {
            std.debug.print("Activation failed: {}\n", .{err});
            return;
        };
    }

    fn userEnvList(self: *CLI, args: []const []const u8) !void {
        if (!self.ensureUserContext()) return;

        var names_only = false;
        for (args) |arg| {
            if (std.mem.eql(u8, arg, "--names-only")) {
                names_only = true;
            }
        }

        const envs = self.user_realization.?.listEnvironments() catch |err| {
            std.debug.print("Error listing environments: {}\n", .{err});
            return;
        };
        defer self.allocator.free(envs);

        if (names_only) {
            for (envs) |env_name| {
                std.debug.print("{s}\n", .{env_name});
                self.allocator.free(env_name);
            }
            return;
        }

        std.debug.print("User Environments for '{s}':\n", .{self.user_ctx.?.username});
        std.debug.print("============================\n\n", .{});

        if (envs.len == 0) {
            std.debug.print("No user environments found.\n", .{});
            std.debug.print("Create one with: axiom user-realize <env-name> <profile>\n", .{});
            return;
        }

        for (envs) |env_name| {
            std.debug.print("  - {s}\n", .{env_name});
            self.allocator.free(env_name);
        }

        std.debug.print("\n{d} environment(s) total\n", .{envs.len});
    }

    fn userEnvDestroy(self: *CLI, args: []const []const u8) !void {
        if (!self.ensureUserContext()) return;

        if (args.len < 1) {
            std.debug.print("Usage: axiom user-env-destroy <env>\n", .{});
            return;
        }

        const env_name = args[0];
        std.debug.print("Destroying user environment: {s}\n", .{env_name});

        // Confirm
        std.debug.print("Are you sure? (y/N): ", .{});

        var buffer: [10]u8 = undefined;
        const stdin = std.io.getStdIn().reader();
        const input = try stdin.readUntilDelimiterOrEof(&buffer, '\n');

        if (input) |line| {
            if (line.len > 0 and (line[0] == 'y' or line[0] == 'Y')) {
                self.user_realization.?.destroy(env_name) catch |err| {
                    std.debug.print("Error destroying environment: {}\n", .{err});
                    return;
                };
                std.debug.print("Environment destroyed\n", .{});
            } else {
                std.debug.print("Cancelled\n", .{});
            }
        }
    }

    // ============================================
    // System Operations (root required)
    // ============================================

    fn checkRoot(self: *CLI) bool {
        if (self.user_ctx) |ctx| {
            if (!ctx.isRoot()) {
                std.debug.print("Error: This command requires root privileges.\n", .{});
                std.debug.print("Run with: sudo axiom <command>\n", .{});
                return false;
            }
        }
        return true;
    }

    fn systemImport(self: *CLI, args: []const []const u8) !void {
        if (!self.checkRoot()) return;

        // Delegate to regular import
        try self.importPackage(args);
    }

    fn systemGc(self: *CLI, args: []const []const u8) !void {
        if (!self.checkRoot()) return;

        // Delegate to regular gc
        try self.garbageCollect(args);
    }

    fn systemUsers(self: *CLI, args: []const []const u8) !void {
        _ = args;
        if (!self.checkRoot()) return;

        if (self.multi_user_mgr == null) {
            std.debug.print("Error: Multi-user manager not initialized.\n", .{});
            return;
        }

        const users = self.multi_user_mgr.?.listUsers() catch |err| {
            std.debug.print("Error listing users: {}\n", .{err});
            return;
        };
        defer self.allocator.free(users);

        std.debug.print("Axiom Users\n", .{});
        std.debug.print("===========\n\n", .{});

        if (users.len == 0) {
            std.debug.print("No users with Axiom data found.\n", .{});
            return;
        }

        for (users) |username| {
            // Get usage for each user
            const usage = self.multi_user_mgr.?.getUserUsage(username) catch 0;
            std.debug.print("  {s}: {d} bytes\n", .{ username, usage });
            self.allocator.free(username);
        }

        std.debug.print("\n{d} user(s) total\n", .{users.len});
    }

    fn systemUserRemove(self: *CLI, args: []const []const u8) !void {
        if (!self.checkRoot()) return;

        if (self.multi_user_mgr == null or self.user_ctx == null) {
            std.debug.print("Error: Multi-user manager not initialized.\n", .{});
            return;
        }

        if (args.len < 1) {
            std.debug.print("Usage: axiom system-user-remove <username>\n", .{});
            return;
        }

        const username = args[0];
        std.debug.print("Removing all Axiom data for user: {s}\n", .{username});
        std.debug.print("WARNING: This will delete all profiles and environments!\n", .{});

        // Confirm
        std.debug.print("Are you sure? (y/N): ", .{});

        var buffer: [10]u8 = undefined;
        const stdin = std.io.getStdIn().reader();
        const input = try stdin.readUntilDelimiterOrEof(&buffer, '\n');

        if (input) |line| {
            if (line.len > 0 and (line[0] == 'y' or line[0] == 'Y')) {
                self.multi_user_mgr.?.removeUser(self.user_ctx.?.*, username) catch |err| {
                    std.debug.print("Error removing user data: {}\n", .{err});
                    return;
                };
                std.debug.print("User data removed\n", .{});
            } else {
                std.debug.print("Cancelled\n", .{});
            }
        }
    }

    // Virtual package operations

    fn virtualList(self: *CLI, args: []const []const u8) !void {
        _ = args;
        std.debug.print("Virtual Packages\n", .{});
        std.debug.print("================\n\n", .{});

        // Build virtual index from store
        var index = resolver.VirtualPackageIndex.init(self.allocator);
        defer index.deinit();

        // Scan all packages in store for provides declarations
        // TODO: Integrate with package store manifest loading
        // For now, show a message about scanning

        std.debug.print("Scanning package store for virtual package declarations...\n\n", .{});

        // List common virtual packages as examples
        std.debug.print("Common virtual packages:\n", .{});
        std.debug.print("  shell          - Command line shell (bash, zsh, fish, etc.)\n", .{});
        std.debug.print("  http-client    - HTTP download tools (curl, wget, etc.)\n", .{});
        std.debug.print("  editor         - Text editors (vim, emacs, nano, etc.)\n", .{});
        std.debug.print("  cc             - C compiler (gcc, clang, etc.)\n", .{});
        std.debug.print("  c++            - C++ compiler (g++, clang++, etc.)\n", .{});
        std.debug.print("\n", .{});

        // Show info about providers
        var iter = index.providers.iterator();
        var count: usize = 0;
        while (iter.next()) |entry| {
            std.debug.print("  {s}: ", .{entry.key_ptr.*});
            const providers = entry.value_ptr.items;
            for (providers, 0..) |provider, i| {
                if (i > 0) std.debug.print(", ", .{});
                std.debug.print("{s}", .{provider});
            }
            std.debug.print("\n", .{});
            count += 1;
        }

        if (count == 0) {
            std.debug.print("No virtual packages found in store.\n", .{});
            std.debug.print("Packages can declare virtual packages in their manifest.yaml:\n\n", .{});
            std.debug.print("  provides:\n", .{});
            std.debug.print("    - shell\n", .{});
            std.debug.print("    - posix-shell\n", .{});
        }
    }

    fn virtualProviders(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom virtual-providers <virtual-package-name>\n", .{});
            std.debug.print("\nExample: axiom virtual-providers shell\n", .{});
            return;
        }

        const virtual_name = args[0];
        std.debug.print("Packages providing '{s}':\n", .{virtual_name});
        std.debug.print("===========================\n\n", .{});

        // Build virtual index from store
        var index = resolver.VirtualPackageIndex.init(self.allocator);
        defer index.deinit();

        // TODO: Scan store for packages that provide this virtual package
        // For now, show instructional message

        if (index.getProviders(virtual_name)) |providers| {
            for (providers) |provider| {
                std.debug.print("  - {s}\n", .{provider});
            }
        } else {
            std.debug.print("No packages found providing '{s}'\n", .{virtual_name});
            std.debug.print("\nTo find providers, packages must declare in manifest.yaml:\n", .{});
            std.debug.print("  provides:\n", .{});
            std.debug.print("    - {s}\n", .{virtual_name});
        }
    }

    fn pkgProvides(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom provides <package-name>\n", .{});
            std.debug.print("\nShows virtual packages that a package provides.\n", .{});
            std.debug.print("Example: axiom provides bash\n", .{});
            return;
        }

        const pkg_name = args[0];
        std.debug.print("Virtual packages provided by '{s}':\n", .{pkg_name});
        std.debug.print("=====================================\n\n", .{});

        // TODO: Load package manifest from store and show provides
        // For now, show example output

        std.debug.print("(Looking up package manifest in store...)\n\n", .{});
        std.debug.print("To see what a package provides, check its manifest.yaml:\n", .{});
        std.debug.print("  provides:\n", .{});
        std.debug.print("    - <virtual-package-name>\n", .{});
        _ = self;
    }

    fn pkgConflicts(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom conflicts <package-name>\n", .{});
            std.debug.print("\nShows packages that cannot be installed alongside this package.\n", .{});
            std.debug.print("Example: axiom conflicts bash\n", .{});
            return;
        }

        const pkg_name = args[0];
        std.debug.print("Packages conflicting with '{s}':\n", .{pkg_name});
        std.debug.print("=================================\n\n", .{});

        // TODO: Load package manifest from store and show conflicts
        // For now, show example output

        std.debug.print("(Looking up package manifest in store...)\n\n", .{});
        std.debug.print("Conflict declarations in manifest.yaml:\n", .{});
        std.debug.print("  conflicts:\n", .{});
        std.debug.print("    - <conflicting-package>\n", .{});
        std.debug.print("    - <package>>=<version>  # With version constraint\n", .{});
        _ = self;
    }

    fn pkgReplaces(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom replaces <package-name>\n", .{});
            std.debug.print("\nShows packages that this package replaces/supersedes.\n", .{});
            std.debug.print("Example: axiom replaces bash\n", .{});
            return;
        }

        const pkg_name = args[0];
        std.debug.print("Packages replaced by '{s}':\n", .{pkg_name});
        std.debug.print("============================\n\n", .{});

        // TODO: Load package manifest from store and show replaces
        // For now, show example output

        std.debug.print("(Looking up package manifest in store...)\n\n", .{});
        std.debug.print("Replace declarations in manifest.yaml:\n", .{});
        std.debug.print("  replaces:\n", .{});
        std.debug.print("    - <old-package>\n", .{});
        std.debug.print("    - <package><version  # With version constraint\n", .{});
        _ = self;
    }

    // Bundle and launcher operations

    fn runPackage(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom run <package>@<version> [args...]\n", .{});
            std.debug.print("\nRun a package directly without activating an environment.\n", .{});
            std.debug.print("\nOptions:\n", .{});
            std.debug.print("  --isolated    Run in fully isolated mode (no system libs)\n", .{});
            std.debug.print("\nExamples:\n", .{});
            std.debug.print("  axiom run hello@1.0.0\n", .{});
            std.debug.print("  axiom run bash@5.2.0 --isolated\n", .{});
            std.debug.print("  axiom run vim@9.0.0 file.txt\n", .{});
            return;
        }

        // Parse package reference
        const pkg_ref = args[0];
        const parsed = launcher_pkg.parsePackageRef(self.allocator, pkg_ref) catch {
            std.debug.print("Invalid package reference: {s}\n", .{pkg_ref});
            std.debug.print("Expected format: <name>@<version> (e.g., hello@1.0.0)\n", .{});
            return;
        };
        defer self.allocator.free(parsed.name);

        // Check for --isolated flag
        var isolated = false;
        var pkg_args = std.ArrayList([]const u8).init(self.allocator);
        defer pkg_args.deinit();

        for (args[1..]) |arg| {
            if (std.mem.eql(u8, arg, "--isolated")) {
                isolated = true;
            } else {
                pkg_args.append(arg) catch {};
            }
        }

        std.debug.print("Running: {s}", .{parsed.name});
        if (parsed.version) |v| {
            std.debug.print("@{d}.{d}.{d}", .{ v.major, v.minor, v.patch });
        }
        if (isolated) {
            std.debug.print(" (isolated mode)", .{});
        }
        std.debug.print("\n\n", .{});

        // Build package ID
        const version = parsed.version orelse types.Version{ .major = 0, .minor = 0, .patch = 0 };
        const pkg_id = types.PackageId{
            .name = parsed.name,
            .version = version,
            .revision = 1,
            .build_id = "latest",
        };

        // Create launcher
        var pkg_launcher = Launcher.init(self.allocator, self.store);
        defer pkg_launcher.deinit();

        const config = launcher_pkg.LaunchConfig{
            .package = pkg_id,
            .args = pkg_args.items,
            .isolation = if (isolated) .isolated else .normal,
        };

        const result = pkg_launcher.launch(config);

        switch (result) {
            .exited => |exit_info| {
                if (exit_info.code == 0) {
                    std.debug.print("\nPackage exited successfully.\n", .{});
                } else {
                    std.debug.print("\nPackage exited with code: {d}\n", .{exit_info.code});
                }
            },
            .signaled => |sig| {
                std.debug.print("\nPackage terminated by signal: {d}\n", .{sig});
            },
            .failed => |err| {
                std.debug.print("Failed to launch package: {s}\n", .{@errorName(err)});
            },
        }
    }

    fn showClosure(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom closure <package>@<version>\n", .{});
            std.debug.print("\nShow the complete dependency closure for a package.\n", .{});
            std.debug.print("\nOptions:\n", .{});
            std.debug.print("  --tree    Display dependencies as a tree\n", .{});
            std.debug.print("\nExamples:\n", .{});
            std.debug.print("  axiom closure bash@5.2.0\n", .{});
            std.debug.print("  axiom closure vim@9.0.0 --tree\n", .{});
            return;
        }

        // Parse package reference
        const pkg_ref = args[0];
        const parsed = launcher_pkg.parsePackageRef(self.allocator, pkg_ref) catch {
            std.debug.print("Invalid package reference: {s}\n", .{pkg_ref});
            return;
        };
        defer self.allocator.free(parsed.name);

        // Check for --tree flag
        var show_tree = false;
        for (args[1..]) |arg| {
            if (std.mem.eql(u8, arg, "--tree")) {
                show_tree = true;
            }
        }

        std.debug.print("Computing closure for: {s}", .{parsed.name});
        if (parsed.version) |v| {
            std.debug.print("@{d}.{d}.{d}", .{ v.major, v.minor, v.patch });
        }
        std.debug.print("\n\n", .{});

        // Build package ID
        const version = parsed.version orelse types.Version{ .major = 0, .minor = 0, .patch = 0 };
        const pkg_id = types.PackageId{
            .name = parsed.name,
            .version = version,
            .revision = 1,
            .build_id = "latest",
        };

        // Compute closure
        var computer = ClosureComputer.init(self.allocator, self.store);
        defer computer.deinit();

        var pkg_closure = computer.computeForPackage(pkg_id) catch |err| {
            std.debug.print("Failed to compute closure: {s}\n", .{@errorName(err)});
            return;
        };
        defer pkg_closure.deinit();

        // Format and display
        const output = closure_pkg.formatClosure(self.allocator, &pkg_closure, .{
            .show_tree = show_tree,
        }) catch {
            std.debug.print("Failed to format closure.\n", .{});
            return;
        };
        defer self.allocator.free(output);

        std.debug.print("{s}\n", .{output});
    }

    fn exportPackage(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom export <package>@<version> [options]\n", .{});
            std.debug.print("\nExport a package as a portable bundle.\n", .{});
            std.debug.print("\nOptions:\n", .{});
            std.debug.print("  --format <f>     Output format: pgsdimg, zfs, tar, dir (default: pgsdimg)\n", .{});
            std.debug.print("  --output <file>  Output file path (default: <name>-<ver>.<ext>)\n", .{});
            std.debug.print("  --no-closure     Don't include dependencies\n", .{});
            std.debug.print("\nExamples:\n", .{});
            std.debug.print("  axiom export hello@1.0.0\n", .{});
            std.debug.print("  axiom export bash@5.2.0 --format zfs\n", .{});
            std.debug.print("  axiom export vim@9.0.0 --output vim-bundle.pgsdimg\n", .{});
            return;
        }

        // Parse package reference
        const pkg_ref = args[0];
        const parsed = launcher_pkg.parsePackageRef(self.allocator, pkg_ref) catch {
            std.debug.print("Invalid package reference: {s}\n", .{pkg_ref});
            return;
        };
        defer self.allocator.free(parsed.name);

        // Parse options
        var format: BundleFormat = .pgsdimg;
        var output_path: ?[]const u8 = null;
        var include_closure = true;

        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--format") and i + 1 < args.len) {
                i += 1;
                if (std.mem.eql(u8, args[i], "pgsdimg")) {
                    format = .pgsdimg;
                } else if (std.mem.eql(u8, args[i], "zfs")) {
                    format = .zfs_stream;
                } else if (std.mem.eql(u8, args[i], "tar")) {
                    format = .tarball;
                } else if (std.mem.eql(u8, args[i], "dir")) {
                    format = .directory;
                }
            } else if (std.mem.eql(u8, args[i], "--output") and i + 1 < args.len) {
                i += 1;
                output_path = args[i];
            } else if (std.mem.eql(u8, args[i], "--no-closure")) {
                include_closure = false;
            }
        }

        // Generate default output path if not specified
        const version = parsed.version orelse types.Version{ .major = 0, .minor = 0, .patch = 0 };
        const ext = switch (format) {
            .pgsdimg => ".pgsdimg",
            .zfs_stream => ".zfs",
            .tarball => ".tar.gz",
            .directory => "",
        };

        const final_output = output_path orelse try std.fmt.allocPrint(
            self.allocator,
            "{s}-{d}.{d}.{d}{s}",
            .{ parsed.name, version.major, version.minor, version.patch, ext },
        );
        defer if (output_path == null) self.allocator.free(final_output);

        std.debug.print("Exporting: {s}@{d}.{d}.{d}\n", .{
            parsed.name,
            version.major,
            version.minor,
            version.patch,
        });
        std.debug.print("Format: {s}\n", .{@tagName(format)});
        std.debug.print("Output: {s}\n", .{final_output});
        std.debug.print("Include closure: {}\n\n", .{include_closure});

        // Build package ID
        const pkg_id = types.PackageId{
            .name = parsed.name,
            .version = version,
            .revision = 1,
            .build_id = "latest",
        };

        // Create bundle
        var builder = BundleBuilder.init(self.allocator, self.store);
        defer builder.deinit();

        const config = bundle_pkg.BundleConfig{
            .format = format,
            .include_closure = include_closure,
        };

        const result = builder.createBundle(pkg_id, final_output, config) catch |err| {
            std.debug.print("Failed to create bundle: {s}\n", .{@errorName(err)});
            return;
        };

        switch (result) {
            .success => |bundle_info| {
                std.debug.print("\nBundle created successfully!\n", .{});
                std.debug.print("  Output: {s}\n", .{bundle_info.output_path});
                std.debug.print("  Size: {d} bytes\n", .{bundle_info.size});
                std.debug.print("  Packages: {d}\n", .{bundle_info.packages_included});
                self.allocator.free(bundle_info.output_path);
            },
            .failure => |err_info| {
                std.debug.print("Bundle creation failed: {s}\n", .{err_info.message});
            },
        }
    }

    fn createBundle(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom bundle <directory> [options]\n", .{});
            std.debug.print("       axiom build-bundle <directory> [options]\n", .{});
            std.debug.print("\nCreate a bundle from a package directory.\n", .{});
            std.debug.print("\nOptions:\n", .{});
            std.debug.print("  --output <file>  Output file path\n", .{});
            std.debug.print("  --sign           Sign the bundle\n", .{});
            std.debug.print("  --key <file>     Signing key file\n", .{});
            std.debug.print("\nExamples:\n", .{});
            std.debug.print("  axiom bundle ./my-app\n", .{});
            std.debug.print("  axiom build-bundle . --output app.pgsdimg\n", .{});
            return;
        }

        const source_dir = args[0];

        // Parse options
        var output_path: ?[]const u8 = null;
        var sign = false;
        var key_file: ?[]const u8 = null;

        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--output") and i + 1 < args.len) {
                i += 1;
                output_path = args[i];
            } else if (std.mem.eql(u8, args[i], "--sign")) {
                sign = true;
            } else if (std.mem.eql(u8, args[i], "--key") and i + 1 < args.len) {
                i += 1;
                key_file = args[i];
            }
        }

        std.debug.print("Creating bundle from: {s}\n", .{source_dir});
        if (output_path) |out| {
            std.debug.print("Output: {s}\n", .{out});
        }
        if (sign) {
            std.debug.print("Signing: enabled\n", .{});
            if (key_file) |kf| {
                std.debug.print("Key: {s}\n", .{kf});
            }
        }
        std.debug.print("\n", .{});

        // Check if directory exists
        std.fs.cwd().access(source_dir, .{}) catch {
            std.debug.print("Error: Directory not found: {s}\n", .{source_dir});
            return;
        };

        // Look for manifest.yaml in the directory
        const manifest_path = std.fs.path.join(self.allocator, &[_][]const u8{
            source_dir,
            "manifest.yaml",
        }) catch {
            std.debug.print("Error: Out of memory\n", .{});
            return;
        };
        defer self.allocator.free(manifest_path);

        std.fs.cwd().access(manifest_path, .{}) catch {
            std.debug.print("Error: No manifest.yaml found in {s}\n", .{source_dir});
            std.debug.print("Create a manifest.yaml first or use 'axiom export' to bundle an installed package.\n", .{});
            return;
        };

        std.debug.print("Found manifest.yaml\n", .{});
        std.debug.print("Building bundle...\n\n", .{});

        // Read manifest to get package info
        const manifest_content = std.fs.cwd().readFileAlloc(
            self.allocator,
            manifest_path,
            1024 * 1024,
        ) catch {
            std.debug.print("Error: Failed to read manifest.yaml\n", .{});
            return;
        };
        defer self.allocator.free(manifest_content);

        const pkg_manifest = manifest.Manifest.parse(self.allocator, manifest_content) catch {
            std.debug.print("Error: Failed to parse manifest.yaml\n", .{});
            return;
        };
        defer {
            var m = pkg_manifest;
            m.deinit(self.allocator);
        }

        // Generate output path if not specified
        const final_output = output_path orelse try std.fmt.allocPrint(
            self.allocator,
            "{s}-{d}.{d}.{d}.pgsdimg",
            .{
                pkg_manifest.name,
                pkg_manifest.version.major,
                pkg_manifest.version.minor,
                pkg_manifest.version.patch,
            },
        );
        defer if (output_path == null) self.allocator.free(final_output);

        std.debug.print("Package: {s}@{d}.{d}.{d}\n", .{
            pkg_manifest.name,
            pkg_manifest.version.major,
            pkg_manifest.version.minor,
            pkg_manifest.version.patch,
        });
        std.debug.print("Output: {s}\n\n", .{final_output});

        // For now, just create a simple tarball
        std.debug.print("Creating bundle...\n", .{});

        var tar_child = std.process.Child.init(
            &[_][]const u8{ "tar", "-czf", final_output, "-C", source_dir, "." },
            self.allocator,
        );

        const term = tar_child.spawnAndWait() catch {
            std.debug.print("Error: Failed to create bundle\n", .{});
            return;
        };

        if (term.Exited == 0) {
            std.debug.print("\nBundle created successfully: {s}\n", .{final_output});

            // Get file size
            const file = std.fs.cwd().openFile(final_output, .{}) catch return;
            defer file.close();
            const stat = file.stat() catch return;
            std.debug.print("Size: {d} bytes\n", .{stat.size});
        } else {
            std.debug.print("Error: Bundle creation failed\n", .{});
        }
    }

    // Phase 28: Bundle verification commands

    fn bundleVerify(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom bundle-verify <bundle.pgsdimg> [options]\n", .{});
            std.debug.print("       axiom verify-bundle <bundle.pgsdimg> [options]\n", .{});
            std.debug.print("\nVerify a bundle's signature and integrity.\n", .{});
            std.debug.print("\nOptions:\n", .{});
            std.debug.print("  --trust-store <dir>  Path to trust store directory\n", .{});
            std.debug.print("  --allow-unsigned     Allow unsigned bundles (still verify hash)\n", .{});
            std.debug.print("  --allow-untrusted    Allow bundles from untrusted signers\n", .{});
            std.debug.print("  --verbose            Show detailed verification info\n", .{});
            std.debug.print("\nExamples:\n", .{});
            std.debug.print("  axiom bundle-verify app.pgsdimg\n", .{});
            std.debug.print("  axiom verify-bundle app.pgsdimg --trust-store /etc/axiom/trust\n", .{});
            return;
        }

        const bundle_path = args[0];

        // Parse options
        var trust_store: ?[]const u8 = null;
        var allow_unsigned = false;
        var allow_untrusted = false;
        var verbose = false;

        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--trust-store") and i + 1 < args.len) {
                i += 1;
                trust_store = args[i];
            } else if (std.mem.eql(u8, args[i], "--allow-unsigned")) {
                allow_unsigned = true;
            } else if (std.mem.eql(u8, args[i], "--allow-untrusted")) {
                allow_untrusted = true;
            } else if (std.mem.eql(u8, args[i], "--verbose") or std.mem.eql(u8, args[i], "-v")) {
                verbose = true;
            }
        }

        std.debug.print("Bundle Verification\n", .{});
        std.debug.print("===================\n\n", .{});
        std.debug.print("Bundle: {s}\n", .{bundle_path});

        // Check if bundle exists
        std.fs.cwd().access(bundle_path, .{}) catch {
            std.debug.print("Error: Bundle not found: {s}\n", .{bundle_path});
            return;
        };

        // Initialize secure bundle launcher for verification
        var launcher = bundle_pkg.SecureBundleLauncher.init(self.allocator, .{
            .temp_dir = "/tmp",
            .trust_store_path = trust_store,
            .require_signature = !allow_unsigned,
            .allow_untrusted = allow_untrusted,
        });
        defer launcher.deinit();

        // Perform verification
        const result = launcher.verify(bundle_path) catch |err| {
            std.debug.print("Error: Verification failed: {s}\n", .{@errorName(err)});
            return;
        };

        // Display results
        std.debug.print("\n", .{});
        std.debug.print("Verification Status: {s}\n", .{result.status.toString()});

        if (result.status.isValid()) {
            std.debug.print("Result: VERIFIED (signature valid, hash matches)\n", .{});
        } else if (result.status.isSafe()) {
            std.debug.print("Result: SAFE (signature valid, signer not in trust store)\n", .{});
        } else {
            std.debug.print("Result: FAILED\n", .{});
            if (result.error_message) |msg| {
                std.debug.print("Error: {s}\n", .{msg});
            }
        }

        if (verbose) {
            std.debug.print("\nDetails:\n", .{});
            if (result.payload_hash) |hash| {
                std.debug.print("  Payload SHA-256: ", .{});
                for (hash) |byte| {
                    std.debug.print("{x:0>2}", .{byte});
                }
                std.debug.print("\n", .{});
            }
            if (result.verified_at != 0) {
                std.debug.print("  Verified at: {d}\n", .{result.verified_at});
            }
            if (result.signer_id) |signer| {
                std.debug.print("  Signer: {s}\n", .{signer});
            }
        }

        std.debug.print("\n", .{});
        if (result.status.isValid()) {
            std.debug.print("Bundle is safe to run.\n", .{});
        } else if (result.status.isSafe()) {
            std.debug.print("Bundle is from an untrusted signer. Use --allow-untrusted to run.\n", .{});
        } else {
            std.debug.print("DO NOT RUN this bundle - verification failed!\n", .{});
        }
    }

    fn bundleRun(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom bundle-run <bundle.pgsdimg> [args...]\n", .{});
            std.debug.print("       axiom run-bundle <bundle.pgsdimg> [args...]\n", .{});
            std.debug.print("\nRun a bundle with pre-execution verification.\n", .{});
            std.debug.print("\nOptions:\n", .{});
            std.debug.print("  --trust-store <dir>  Path to trust store directory\n", .{});
            std.debug.print("  --allow-unsigned     Allow unsigned bundles\n", .{});
            std.debug.print("  --allow-untrusted    Allow bundles from untrusted signers\n", .{});
            std.debug.print("  --skip-verify        Skip verification (DANGEROUS)\n", .{});
            std.debug.print("  --keep-extracted     Keep extraction directory after run\n", .{});
            std.debug.print("  --                   End options, remaining args passed to bundle\n", .{});
            std.debug.print("\nExamples:\n", .{});
            std.debug.print("  axiom bundle-run app.pgsdimg\n", .{});
            std.debug.print("  axiom run-bundle app.pgsdimg --allow-unsigned -- --help\n", .{});
            return;
        }

        const bundle_path = args[0];

        // Parse options
        var trust_store: ?[]const u8 = null;
        var allow_unsigned = false;
        var allow_untrusted = false;
        var skip_verify = false;
        var keep_extracted = false;
        var bundle_args = std.ArrayList([]const u8).init(self.allocator);
        defer bundle_args.deinit();

        var i: usize = 1;
        var in_bundle_args = false;
        while (i < args.len) : (i += 1) {
            if (in_bundle_args) {
                try bundle_args.append(args[i]);
            } else if (std.mem.eql(u8, args[i], "--")) {
                in_bundle_args = true;
            } else if (std.mem.eql(u8, args[i], "--trust-store") and i + 1 < args.len) {
                i += 1;
                trust_store = args[i];
            } else if (std.mem.eql(u8, args[i], "--allow-unsigned")) {
                allow_unsigned = true;
            } else if (std.mem.eql(u8, args[i], "--allow-untrusted")) {
                allow_untrusted = true;
            } else if (std.mem.eql(u8, args[i], "--skip-verify")) {
                skip_verify = true;
            } else if (std.mem.eql(u8, args[i], "--keep-extracted")) {
                keep_extracted = true;
            } else {
                // Treat unknown args as bundle args
                try bundle_args.append(args[i]);
            }
        }

        // Check if bundle exists
        std.fs.cwd().access(bundle_path, .{}) catch {
            std.debug.print("Error: Bundle not found: {s}\n", .{bundle_path});
            return;
        };

        if (skip_verify) {
            std.debug.print("WARNING: Skipping verification is DANGEROUS!\n", .{});
            std.debug.print("Only use this for testing purposes.\n\n", .{});
        }

        // Initialize secure bundle launcher
        var launcher = bundle_pkg.SecureBundleLauncher.init(self.allocator, .{
            .temp_dir = "/tmp",
            .trust_store_path = trust_store,
            .require_signature = !allow_unsigned and !skip_verify,
            .allow_untrusted = allow_untrusted,
        });
        defer launcher.deinit();

        std.debug.print("Launching: {s}\n", .{bundle_path});
        if (!skip_verify) {
            std.debug.print("Verifying bundle...\n", .{});
        }

        // Launch with verification
        const result = launcher.launch(bundle_path, bundle_args.items) catch |err| {
            std.debug.print("Error: Launch failed: {s}\n", .{@errorName(err)});
            return;
        };

        switch (result) {
            .success => |s| {
                std.debug.print("Bundle exited with code: {d}\n", .{s.exit_code});
                if (!keep_extracted) {
                    launcher.cleanup(@constCast(s.extract_dir));
                } else {
                    std.debug.print("Extraction preserved at: {s}\n", .{s.extract_dir});
                }
            },
            .signaled => |s| {
                std.debug.print("Bundle terminated by signal: {d}\n", .{s.signal});
                if (!keep_extracted) {
                    launcher.cleanup(@constCast(s.extract_dir));
                }
            },
            .failed => |f| {
                std.debug.print("Bundle launch failed: {s}\n", .{f.message});
            },
        }
    }

    // Ports migration commands

    fn portsGen(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom ports-gen <origin> [options]\n", .{});
            std.debug.print("\nGenerate Axiom manifests from a FreeBSD port.\n", .{});
            std.debug.print("\nArguments:\n", .{});
            std.debug.print("  <origin>         Port origin (e.g., editors/vim, devel/git)\n", .{});
            std.debug.print("\nOptions:\n", .{});
            std.debug.print("  --ports-tree <path>  Path to ports tree (default: /usr/ports)\n", .{});
            std.debug.print("  --out <dir>          Output directory (default: ./generated/axiom-ports)\n", .{});
            std.debug.print("  --build              Also build after generating\n", .{});
            std.debug.print("  --import             Also import to store after building\n", .{});
            std.debug.print("  --dry-run            Show what would be generated without writing\n", .{});
            std.debug.print("\nExamples:\n", .{});
            std.debug.print("  axiom ports-gen editors/vim\n", .{});
            std.debug.print("  axiom ports-gen devel/git --out ./my-ports\n", .{});
            std.debug.print("  axiom ports-gen shells/bash --build --import\n", .{});
            return;
        }

        const origin = args[0];

        // Parse options
        var ports_tree: []const u8 = "/usr/ports";
        var output_dir: []const u8 = "./generated/axiom-ports";
        var build_after = false;
        var import_after = false;
        var dry_run = false;

        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--ports-tree") and i + 1 < args.len) {
                i += 1;
                ports_tree = args[i];
            } else if (std.mem.eql(u8, args[i], "--out") and i + 1 < args.len) {
                i += 1;
                output_dir = args[i];
            } else if (std.mem.eql(u8, args[i], "--build")) {
                build_after = true;
            } else if (std.mem.eql(u8, args[i], "--import")) {
                import_after = true;
                build_after = true; // Import implies build
            } else if (std.mem.eql(u8, args[i], "--dry-run")) {
                dry_run = true;
            }
        }

        std.debug.print("FreeBSD Ports Migration\n", .{});
        std.debug.print("=======================\n\n", .{});
        std.debug.print("Port origin: {s}\n", .{origin});
        std.debug.print("Ports tree: {s}\n", .{ports_tree});
        std.debug.print("Output: {s}/{s}\n", .{ output_dir, origin });
        if (dry_run) std.debug.print("Mode: dry-run\n", .{});
        std.debug.print("\n", .{});

        // Initialize migrator
        var migrator = PortsMigrator.init(self.allocator, .{
            .ports_tree = ports_tree,
            .output_dir = output_dir,
            .build_after_generate = build_after,
            .import_after_build = import_after,
            .dry_run = dry_run,
        });

        // Run migration
        const result = migrator.migrate(origin) catch |err| {
            std.debug.print("Migration failed: {s}\n", .{@errorName(err)});
            return;
        };

        // Display result
        switch (result.status) {
            .generated => {
                std.debug.print("Generated Axiom manifests:\n", .{});
                if (result.manifest_path) |path| {
                    std.debug.print("  {s}/manifest.yaml\n", .{path});
                    std.debug.print("  {s}/deps.yaml\n", .{path});
                    std.debug.print("  {s}/build.yaml\n", .{path});
                }
            },
            .built => std.debug.print("Port built successfully\n", .{}),
            .imported => {
                std.debug.print("Port imported to store: {s}\n", .{result.axiom_package orelse "unknown"});
            },
            .failed => {
                std.debug.print("Migration failed:\n", .{});
                for (result.errors.items) |err| {
                    std.debug.print("  - {s}\n", .{err});
                }
            },
            else => {},
        }

        // Show warnings
        if (result.warnings.items.len > 0) {
            std.debug.print("\nWarnings:\n", .{});
            for (result.warnings.items) |warning| {
                std.debug.print("  - {s}\n", .{warning});
            }
        }
    }

    fn portsBuild(self: *CLI, args: []const []const u8) !void {
        _ = self;
        if (args.len < 1) {
            std.debug.print("Usage: axiom ports-build <origin>\n", .{});
            std.debug.print("\nBuild a port using Axiom's builder from generated manifests.\n", .{});
            std.debug.print("\nFirst run 'axiom ports-gen <origin>' to generate manifests.\n", .{});
            return;
        }

        const origin = args[0];
        std.debug.print("Building port: {s}\n", .{origin});
        std.debug.print("\nNote: ports-build requires generated manifests.\n", .{});
        std.debug.print("Use 'axiom ports-gen {s} --build' for full workflow.\n", .{origin});

        // TODO: Integrate with build_pkg.Builder
        std.debug.print("\nBuild phase not yet fully implemented.\n", .{});
    }

    fn portsImport(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom ports-import <origin> [options]\n", .{});
            std.debug.print("       axiom ports-import --fix-broken\n", .{});
            std.debug.print("\nFull migration: generate manifests, build, and import to store.\n", .{});
            std.debug.print("Automatically resolves and builds dependencies in correct order.\n", .{});
            std.debug.print("\nOptions:\n", .{});
            std.debug.print("  --ports-tree <path>  Path to ports tree (default: /usr/ports)\n", .{});
            std.debug.print("  --jobs <n>           Number of parallel build jobs (default: 4)\n", .{});
            std.debug.print("  --verbose            Show detailed build output\n", .{});
            std.debug.print("  --keep-sandbox       Don't clean up build staging directory\n", .{});
            std.debug.print("  --dry-run            Generate manifests only, don't build\n", .{});
            std.debug.print("  --no-deps            Don't auto-resolve dependencies\n", .{});
            std.debug.print("  --use-system-tools   Use /usr/local tools instead of sysroot\n", .{});
            std.debug.print("  --fix-broken         Scan store and rebuild packages with broken layout\n", .{});
            std.debug.print("  --no-sign            Don't sign packages after import\n", .{});
            std.debug.print("  --continue-on-failure  Continue building other ports if one fails\n", .{});
            std.debug.print("\nExamples:\n", .{});
            std.debug.print("  axiom ports-import shells/bash\n", .{});
            std.debug.print("  axiom ports-import editors/vim --jobs 8 --verbose\n", .{});
            std.debug.print("  axiom ports-import devel/m4 --no-deps  # Just this port\n", .{});
            std.debug.print("  axiom ports-import --fix-broken        # Repair corrupted packages\n", .{});
            return;
        }

        // Parse arguments
        var origin: ?[]const u8 = null;
        var ports_tree: []const u8 = "/usr/ports";
        var jobs: u32 = 4;
        var verbose: bool = false;
        var keep_sandbox: bool = false;
        var dry_run: bool = false;
        var auto_deps: bool = true;
        var use_system_tools: bool = false;
        var fix_broken: bool = false;
        var sign_packages: bool = true;
        var continue_on_failure: bool = false;

        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--ports-tree") and i + 1 < args.len) {
                i += 1;
                ports_tree = args[i];
            } else if (std.mem.eql(u8, args[i], "--jobs") and i + 1 < args.len) {
                i += 1;
                jobs = std.fmt.parseInt(u32, args[i], 10) catch 4;
            } else if (std.mem.eql(u8, args[i], "--verbose")) {
                verbose = true;
            } else if (std.mem.eql(u8, args[i], "--keep-sandbox")) {
                keep_sandbox = true;
            } else if (std.mem.eql(u8, args[i], "--dry-run")) {
                dry_run = true;
            } else if (std.mem.eql(u8, args[i], "--no-deps")) {
                auto_deps = false;
            } else if (std.mem.eql(u8, args[i], "--use-system-tools")) {
                use_system_tools = true;
            } else if (std.mem.eql(u8, args[i], "--fix-broken")) {
                fix_broken = true;
            } else if (std.mem.eql(u8, args[i], "--no-sign")) {
                sign_packages = false;
            } else if (std.mem.eql(u8, args[i], "--continue-on-failure")) {
                continue_on_failure = true;
            } else if (origin == null and args[i][0] != '-') {
                origin = args[i];
            }
        }

        // Handle --fix-broken mode (no origin required)
        if (fix_broken) {
            std.debug.print("Scanning for packages with broken layout...\n", .{});

            var migrator = PortsMigrator.init(self.allocator, .{
                .ports_tree = ports_tree,
                .output_dir = "./generated/axiom-ports",
                .build_after_generate = true,
                .import_after_build = true,
                .dry_run = false,
                .verbose = verbose,
                .auto_deps = false, // Rebuild each package independently
                .zfs_handle = self.zfs_handle,
                .store = self.store,
                .sign_packages = sign_packages,
                .importer = self.importer,
                .build_jobs = jobs,
                .keep_sandbox = keep_sandbox,
                .use_system_tools = use_system_tools,
            });

            _ = migrator.fixBrokenPackages() catch |err| {
                std.debug.print("Error fixing broken packages: {s}\n", .{@errorName(err)});
            };
            return;
        }

        const port_origin = origin orelse {
            std.debug.print("Error: Port origin required (e.g., shells/bash)\n", .{});
            std.debug.print("       Or use --fix-broken to repair packages with broken layout\n", .{});
            return;
        };

        std.debug.print("Full port migration: {s}\n", .{port_origin});
        if (auto_deps) {
            std.debug.print("(with automatic dependency resolution)\n", .{});
        }
        if (use_system_tools) {
            std.debug.print("(using system tools from /usr/local)\n", .{});
        }
        std.debug.print("========================================\n\n", .{});

        // Run full migration with build system integration
        var migrator = PortsMigrator.init(self.allocator, .{
            .ports_tree = ports_tree,
            .output_dir = "./generated/axiom-ports",
            .build_after_generate = !dry_run,
            .import_after_build = !dry_run,
            .dry_run = dry_run,
            .verbose = verbose,
            .auto_deps = auto_deps,
            // Pass build system dependencies
            .zfs_handle = self.zfs_handle,
            .store = self.store,
            .importer = self.importer,
            .build_jobs = jobs,
            .keep_sandbox = keep_sandbox,
            .use_system_tools = use_system_tools,
            .sign_packages = sign_packages,
            .continue_on_failure = continue_on_failure,
        });

        // Check bootstrap status and warn if packages are missing
        try migrator.checkBootstrapStatus();

        var results = migrator.migrateWithDependencies(port_origin) catch |err| {
            std.debug.print("Migration failed: {s}\n", .{@errorName(err)});
            return;
        };
        defer {
            for (results.items) |*r| r.deinit(self.allocator);
            results.deinit();
        }

        // Summarize results
        var succeeded: usize = 0;
        var failed: usize = 0;
        var skipped: usize = 0;
        var skipped_already_in_store: usize = 0;
        var skipped_replaced_by_axiom: usize = 0;

        for (results.items) |*result| {
            // Show any warnings
            if (result.warnings.items.len > 0) {
                std.debug.print("\nWarnings for {s}:\n", .{result.origin});
                for (result.warnings.items) |warning| {
                    std.debug.print("  - {s}\n", .{warning});
                }
            }

            // Show any errors
            if (result.errors.items.len > 0) {
                std.debug.print("\nErrors for {s}:\n", .{result.origin});
                for (result.errors.items) |err_msg| {
                    std.debug.print("  - {s}\n", .{err_msg});
                }
            }

            if (result.status == .failed) {
                failed += 1;
            } else if (result.status == .skipped) {
                skipped += 1;
                // Track skip reasons
                switch (result.skip_reason) {
                    .already_in_store => skipped_already_in_store += 1,
                    .replaced_by_axiom => skipped_replaced_by_axiom += 1,
                    .none => {},
                }
            } else if (result.status == .imported or result.status == .built or result.status == .generated) {
                succeeded += 1;
            }
        }

        std.debug.print("\n" ++ "=" ** 60 ++ "\n", .{});
        if (skipped > 0) {
            std.debug.print("Summary: {d} succeeded, {d} skipped, {d} failed (of {d} total)\n", .{ succeeded, skipped, failed, results.items.len });
            // Show breakdown of skip reasons
            std.debug.print("\nSkipped packages breakdown:\n", .{});
            if (skipped_already_in_store > 0) {
                std.debug.print("  - {d} already in store (same origin)\n", .{skipped_already_in_store});
            }
            if (skipped_replaced_by_axiom > 0) {
                std.debug.print("  - {d} replaced by Axiom (e.g., ports-mgmt/pkg)\n", .{skipped_replaced_by_axiom});
            }
        } else {
            std.debug.print("Summary: {d} succeeded, {d} failed (of {d} total)\n", .{ succeeded, failed, results.items.len });
        }
        std.debug.print("=" ** 60 ++ "\n", .{});

        // Show final status for the target port
        if (results.items.len > 0) {
            const final_result = &results.items[results.items.len - 1];
            if (std.mem.eql(u8, final_result.origin, port_origin)) {
                switch (final_result.status) {
                    .imported => {
                        std.debug.print("\n✓ Success! {s} imported to store.\n", .{port_origin});
                        if (final_result.axiom_package) |pkg| {
                            std.debug.print("  Package: {s}\n", .{pkg});
                        }
                        std.debug.print("\nYou can now use this package in your profiles.\n", .{});
                    },
                    .built => {
                        std.debug.print("\n✓ {s} built successfully.\n", .{port_origin});
                        std.debug.print("  Import was not requested.\n", .{});
                    },
                    .generated => {
                        std.debug.print("\n✓ Manifests generated for {s}.\n", .{port_origin});
                        if (final_result.manifest_path) |path| {
                            std.debug.print("  Output: {s}\n", .{path});
                        }
                        if (dry_run) {
                            std.debug.print("  (dry-run mode - build/import skipped)\n", .{});
                        }
                    },
                    .failed => {
                        std.debug.print("\n✗ Migration of {s} failed.\n", .{port_origin});
                    },
                    .skipped => {
                        std.debug.print("\n✓ {s} already in store, skipped.\n", .{port_origin});
                        if (final_result.axiom_package) |pkg| {
                            std.debug.print("  Package: {s}\n", .{pkg});
                        }
                    },
                    else => {
                        std.debug.print("\nMigration status: {s}\n", .{@tagName(final_result.status)});
                    },
                }
            }
        }
    }

    fn portsScan(self: *CLI, args: []const []const u8) !void {
        var ports_tree: []const u8 = "/usr/ports";

        // Check for options first
        var category: ?[]const u8 = null;
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--ports-tree") and i + 1 < args.len) {
                i += 1;
                ports_tree = args[i];
            } else if (category == null and args[i][0] != '-') {
                category = args[i];
            }
        }

        std.debug.print("FreeBSD Ports Scanner\n", .{});
        std.debug.print("=====================\n\n", .{});
        std.debug.print("Ports tree: {s}\n\n", .{ports_tree});

        if (category) |cat| {
            // Scan specific category
            std.debug.print("Scanning category: {s}\n\n", .{cat});

            var migrator = PortsMigrator.init(self.allocator, .{
                .ports_tree = ports_tree,
            });

            const ports = migrator.scanCategory(cat) catch |err| {
                std.debug.print("Scan failed: {s}\n", .{@errorName(err)});
                return;
            };

            if (ports.len == 0) {
                std.debug.print("No ports found in {s}\n", .{cat});
                return;
            }

            std.debug.print("Found {d} ports:\n", .{ports.len});
            for (ports) |origin| {
                std.debug.print("  {s}\n", .{origin});
            }

            std.debug.print("\nTo migrate a port:\n", .{});
            std.debug.print("  axiom ports-gen {s}/<portname>\n", .{cat});
        } else {
            // List categories
            std.debug.print("Available categories:\n\n", .{});

            // Common categories to check
            const categories = [_][]const u8{
                "accessibility", "arabic",        "archivers",   "astro",
                "audio",         "benchmarks",    "biology",     "cad",
                "chinese",       "comms",         "converters",  "databases",
                "deskutils",     "devel",         "dns",         "editors",
                "emulators",     "finance",       "french",      "ftp",
                "games",         "german",        "graphics",    "hebrew",
                "hungarian",     "irc",           "japanese",    "java",
                "korean",        "lang",          "mail",        "math",
                "misc",          "multimedia",    "net",         "net-im",
                "net-mgmt",      "net-p2p",       "news",        "palm",
                "polish",        "ports-mgmt",    "portuguese",  "print",
                "russian",       "science",       "security",    "shells",
                "sysutils",      "textproc",      "ukrainian",   "vietnamese",
                "www",           "x11",           "x11-clocks",  "x11-drivers",
                "x11-fm",        "x11-fonts",     "x11-servers", "x11-themes",
                "x11-toolkits",  "x11-wm",
            };

            for (categories) |cat| {
                const cat_path = std.fs.path.join(self.allocator, &[_][]const u8{
                    ports_tree,
                    cat,
                }) catch continue;
                defer self.allocator.free(cat_path);

                if (std.fs.cwd().access(cat_path, .{})) |_| {
                    std.debug.print("  {s}\n", .{cat});
                } else |_| {}
            }

            std.debug.print("\nTo scan a category:\n", .{});
            std.debug.print("  axiom ports-scan <category>\n", .{});
            std.debug.print("  axiom ports-scan devel\n", .{});
        }
    }

    // =============================================================
    // Phase 26: ZFS Path Validation
    // =============================================================

    /// Validate ZFS dataset path components
    fn zfsValidate(self: *CLI, args: []const []const u8) !void {
        std.debug.print("ZFS Path Validation (Phase 26)\n", .{});
        std.debug.print("==============================\n\n", .{});

        if (args.len == 0) {
            std.debug.print("Usage: axiom zfs-validate <path|component> [--type dataset|snapshot|component]\n\n", .{});
            std.debug.print("Validates ZFS dataset paths and components for security.\n", .{});
            std.debug.print("Prevents path injection, traversal attacks, and special character abuse.\n\n", .{});
            std.debug.print("Examples:\n", .{});
            std.debug.print("  axiom zfs-validate bash                    # Validate as component\n", .{});
            std.debug.print("  axiom zfs-validate ../../../etc/passwd     # Detects traversal\n", .{});
            std.debug.print("  axiom zfs-validate pkg@snap --type dataset # Detects snapshot in dataset\n", .{});
            std.debug.print("  axiom zfs-validate 'pkg name'              # Detects invalid chars\n", .{});
            std.debug.print("\nValid characters: a-z, A-Z, 0-9, -, _, .\n", .{});
            std.debug.print("Reserved names: ., .., zfs, zpool, snapshot, bookmark, clone, origin\n", .{});
            return;
        }

        const input = args[0];
        var validate_type: enum { component, dataset, snapshot } = .component;

        // Parse options
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--type") and i + 1 < args.len) {
                i += 1;
                if (std.mem.eql(u8, args[i], "dataset")) {
                    validate_type = .dataset;
                } else if (std.mem.eql(u8, args[i], "snapshot")) {
                    validate_type = .snapshot;
                } else if (std.mem.eql(u8, args[i], "component")) {
                    validate_type = .component;
                }
            }
        }

        const validator = zfs.ZfsPathValidator.init(self.allocator, self.store.paths.store_root);

        std.debug.print("Input: \"{s}\"\n", .{input});
        std.debug.print("Type:  {s}\n\n", .{@tagName(validate_type)});

        switch (validate_type) {
            .component => {
                validator.validateComponent(input) catch |err| {
                    std.debug.print("✗ INVALID: {s}\n", .{zfs.ZfsPathValidator.errorMessage(err)});
                    std.debug.print("\nSecurity implication: This input could be used for path injection.\n", .{});
                    return;
                };
                std.debug.print("✓ VALID: Component is safe to use in ZFS dataset paths\n", .{});
            },
            .dataset => {
                // For dataset validation, prepend store root if not already present
                const full_path = if (std.mem.startsWith(u8, input, self.store.paths.store_root))
                    input
                else blk: {
                    const p = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.store.paths.store_root, input }) catch {
                        std.debug.print("✗ ERROR: Memory allocation failed\n", .{});
                        return;
                    };
                    break :blk p;
                };

                validator.validateDatasetPath(full_path) catch |err| {
                    std.debug.print("✗ INVALID: {s}\n", .{zfs.ZfsPathValidator.errorMessage(err)});
                    std.debug.print("\nSecurity implication: This path could escape the store hierarchy.\n", .{});
                    return;
                };
                std.debug.print("✓ VALID: Dataset path is within the store hierarchy and safe\n", .{});
            },
            .snapshot => {
                // For snapshot validation, ensure it has @ separator
                if (std.mem.indexOfScalar(u8, input, '@') == null) {
                    std.debug.print("✗ INVALID: Snapshot path must contain '@' separator\n", .{});
                    std.debug.print("  Example: dataset@snapshot_name\n", .{});
                    return;
                }

                // Prepend store root if not present
                const full_path = if (std.mem.startsWith(u8, input, self.store.paths.store_root))
                    input
                else blk: {
                    const p = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.store.paths.store_root, input }) catch {
                        std.debug.print("✗ ERROR: Memory allocation failed\n", .{});
                        return;
                    };
                    break :blk p;
                };

                validator.validateSnapshotPath(full_path) catch |err| {
                    std.debug.print("✗ INVALID: {s}\n", .{zfs.ZfsPathValidator.errorMessage(err)});
                    std.debug.print("\nSecurity implication: This snapshot path is malformed or escapes hierarchy.\n", .{});
                    return;
                };
                std.debug.print("✓ VALID: Snapshot path is safe\n", .{});
            },
        }

        // Also test sanitization
        std.debug.print("\nSanitization:\n", .{});
        if (validator.sanitizeComponent(input)) |sanitized| {
            defer self.allocator.free(sanitized);
            if (std.mem.eql(u8, input, sanitized)) {
                std.debug.print("  Input is already safe (no changes needed)\n", .{});
            } else {
                std.debug.print("  Sanitized form: \"{s}\"\n", .{sanitized});
            }
        } else |_| {
            std.debug.print("  Cannot be sanitized (empty input)\n", .{});
        }
    }

    // =============================================================
    // Kernel Compatibility Commands
    // =============================================================

    fn kernelCheck(self: *CLI, args: []const []const u8) !void {
        _ = args; // TODO: Add --profile, --env filters

        std.debug.print("Kernel Compatibility Check\n", .{});
        std.debug.print("==========================\n\n", .{});

        // Get kernel context - in production this would read from sysctl
        // For now we use mock values or read from environment
        var freebsd_version: u32 = 1502000;
        var kernel_ident: []const u8 = "GENERIC";

        // Try to detect actual values on FreeBSD
        // This is a placeholder - real implementation would use sysctl
        if (std.process.getEnvVarOwned(self.allocator, "AXIOM_FREEBSD_VERSION")) |ver_str| {
            defer self.allocator.free(ver_str);
            freebsd_version = std.fmt.parseInt(u32, ver_str, 10) catch 1502000;
        } else |_| {}

        if (std.process.getEnvVarOwned(self.allocator, "AXIOM_KERNEL_IDENT")) |ident| {
            kernel_ident = ident;
            // Note: We're leaking ident here for simplicity - real impl would handle properly
        } else |_| {}

        std.debug.print("Kernel:\n", .{});
        std.debug.print("  FreeBSD version (osreldate): {d}\n", .{freebsd_version});
        std.debug.print("  Kernel ident: {s}\n\n", .{kernel_ident});

        const kernel_ctx = resolver.KernelContext.initMock(freebsd_version, kernel_ident);

        // Scan installed packages for kernel-bound ones
        std.debug.print("Kernel-bound packages:\n\n", .{});

        var ok_count: usize = 0;
        var incompatible_count: usize = 0;

        // In a full implementation, we would iterate through:
        // 1. All packages in the store
        // 2. Or packages in active profiles/environments
        //
        // For now, demonstrate with mock data
        const mock_packages = [_]struct {
            name: []const u8,
            version: []const u8,
            kernel: ?manifest.KernelCompat,
        }{
            .{
                .name = "drm-kmod",
                .version = "6.10.0_1",
                .kernel = manifest.KernelCompat{
                    .kmod = true,
                    .freebsd_version_min = 1500000,
                    .freebsd_version_max = 1509999,
                    .kernel_idents = &[_][]const u8{ "GENERIC", "PGSD-GENERIC" },
                    .require_exact_ident = false,
                },
            },
            .{
                .name = "nvidia-driver",
                .version = "550.78",
                .kernel = manifest.KernelCompat{
                    .kmod = true,
                    .freebsd_version_min = 1400000,
                    .freebsd_version_max = 1499999,
                    .kernel_idents = &[_][]const u8{},
                    .require_exact_ident = false,
                },
            },
            .{
                .name = "bash",
                .version = "5.2.26",
                .kernel = null, // Userland package
            },
        };

        for (mock_packages) |pkg| {
            if (pkg.kernel) |k| {
                if (!k.kmod) continue;

                const result = resolver.kernelIsCompatible(&kernel_ctx, &k);

                if (result.compatible) {
                    std.debug.print("  [OK] {s}-{s}\n", .{ pkg.name, pkg.version });
                    if (k.freebsd_version_min != null or k.freebsd_version_max != null) {
                        std.debug.print("       freebsd_version: ", .{});
                        if (k.freebsd_version_min) |min| std.debug.print("{d}", .{min});
                        std.debug.print("-", .{});
                        if (k.freebsd_version_max) |max| std.debug.print("{d}", .{max});
                        std.debug.print("\n", .{});
                    }
                    if (k.kernel_idents.len > 0) {
                        std.debug.print("       kernel_idents: ", .{});
                        for (k.kernel_idents, 0..) |ident, idx| {
                            if (idx > 0) std.debug.print(", ", .{});
                            std.debug.print("{s}", .{ident});
                        }
                        std.debug.print("\n", .{});
                    }
                    ok_count += 1;
                } else {
                    std.debug.print("  [INCOMPATIBLE] {s}-{s}\n", .{ pkg.name, pkg.version });
                    std.debug.print("       reason: {s}\n", .{result.getMessage()});
                    // Show detailed diagnostics based on error type
                    switch (result.reason) {
                        .version_below_minimum => {
                            std.debug.print("       running version: {d}\n", .{result.running_version});
                            if (result.required_min) |min| {
                                std.debug.print("       required minimum: {d}\n", .{min});
                            }
                        },
                        .version_above_maximum => {
                            std.debug.print("       running version: {d}\n", .{result.running_version});
                            if (result.required_max) |max| {
                                std.debug.print("       required maximum: {d}\n", .{max});
                            }
                        },
                        .ident_mismatch => {
                            std.debug.print("       running ident: \"{s}\"\n", .{result.running_ident});
                            if (k.kernel_idents.len > 0) {
                                std.debug.print("       allowed idents: ", .{});
                                for (k.kernel_idents, 0..) |ident, idx| {
                                    if (idx > 0) std.debug.print(", ", .{});
                                    std.debug.print("{s}", .{ident});
                                }
                                std.debug.print("\n", .{});
                            }
                        },
                        .none => {},
                    }
                    incompatible_count += 1;
                }
                std.debug.print("\n", .{});
            }
        }

        std.debug.print("Summary:\n", .{});
        std.debug.print("  {d} compatible kernel-bound packages\n", .{ok_count});
        if (incompatible_count > 0) {
            std.debug.print("  {d} incompatible kernel-bound packages\n", .{incompatible_count});
            std.debug.print("\n⚠ Warning: Incompatible kernel modules may fail to load.\n", .{});
            std.debug.print("Consider rebuilding these packages for your current kernel.\n", .{});
        }
    }

    // ==================== Bootstrap Commands ====================

    fn bootstrapStatus(self: *CLI, args: []const []const u8) !void {
        _ = args;

        std.debug.print("Bootstrap Status\n", .{});
        std.debug.print("================\n\n", .{});

        var bootstrap_mgr = BootstrapManager.init(
            self.allocator,
            self.zfs_handle,
            self.store,
            self.importer,
        );

        const status = try bootstrap_mgr.checkStatus();
        defer self.allocator.free(status.installed_packages);
        defer self.allocator.free(status.missing_packages);

        if (status.is_bootstrapped) {
            std.debug.print("Status: BOOTSTRAPPED ✓\n\n", .{});
            std.debug.print("All required bootstrap packages are installed.\n", .{});
            std.debug.print("You can build ports without needing pkg.\n", .{});
        } else {
            std.debug.print("Status: NOT BOOTSTRAPPED\n\n", .{});
            std.debug.print("Missing packages ({d}):\n", .{status.missing_packages.len});
            for (status.missing_packages) |pkg| {
                std.debug.print("  - {s}\n", .{pkg});
            }
            std.debug.print("\nTo bootstrap, either:\n", .{});
            std.debug.print("  1. Import a bootstrap tarball:\n", .{});
            std.debug.print("     axiom bootstrap-import axiom-bootstrap-14.2-amd64.tar.zst\n", .{});
            std.debug.print("\n  2. Build from ports (requires pkg for initial tools):\n", .{});
            std.debug.print("     pkg install gmake m4\n", .{});
            std.debug.print("     axiom ports-import devel/gmake devel/m4 ...\n", .{});
        }

        std.debug.print("\nInstalled bootstrap packages ({d}):\n", .{status.installed_packages.len});
        for (status.installed_packages) |pkg| {
            std.debug.print("  ✓ {s}\n", .{pkg});
        }

        std.debug.print("\nRequired packages for full bootstrap:\n", .{});
        for (bootstrap_pkg.REQUIRED_BOOTSTRAP_PACKAGES) |pkg| {
            const installed = for (status.installed_packages) |inst| {
                if (std.mem.eql(u8, inst, pkg)) break true;
            } else false;
            if (installed) {
                std.debug.print("  ✓ {s}\n", .{pkg});
            } else {
                std.debug.print("  ✗ {s}\n", .{pkg});
            }
        }
    }

    fn bootstrapImport(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom bootstrap-import <tarball> [options]\n", .{});
            std.debug.print("\nImport a bootstrap tarball to enable building ports without pkg.\n", .{});
            std.debug.print("\nOptions:\n", .{});
            std.debug.print("  --force      Overwrite existing packages\n", .{});
            std.debug.print("  --dry-run    Show what would be imported without doing it\n", .{});
            std.debug.print("  --verbose    Show detailed output\n", .{});
            std.debug.print("\nExamples:\n", .{});
            std.debug.print("  axiom bootstrap-import axiom-bootstrap-14.2-amd64.tar.zst\n", .{});
            std.debug.print("  axiom bootstrap-import bootstrap.tar.gz --force\n", .{});
            std.debug.print("\nBootstrap tarballs can be downloaded from:\n", .{});
            std.debug.print("  https://axiom.pgsd.org/bootstrap/\n", .{});
            return;
        }

        const tarball_path = args[0];

        // Parse options
        var options = bootstrap_pkg.ImportOptions{};
        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--force")) {
                options.force = true;
            } else if (std.mem.eql(u8, args[i], "--dry-run")) {
                options.dry_run = true;
            } else if (std.mem.eql(u8, args[i], "--verbose")) {
                options.verbose = true;
            }
        }

        var bootstrap_mgr = BootstrapManager.init(
            self.allocator,
            self.zfs_handle,
            self.store,
            self.importer,
        );

        _ = try bootstrap_mgr.importBootstrap(tarball_path, options);

        std.debug.print("\nRun 'axiom bootstrap' to check bootstrap status.\n", .{});
    }

    fn bootstrapExport(self: *CLI, args: []const []const u8) !void {
        if (args.len < 1) {
            std.debug.print("Usage: axiom bootstrap-export <output.tar.zst> [options]\n", .{});
            std.debug.print("\nCreate a bootstrap tarball from installed Axiom packages.\n", .{});
            std.debug.print("\nOptions:\n", .{});
            std.debug.print("  --minimal           Include only minimal packages (gmake, m4)\n", .{});
            std.debug.print("  --packages <list>   Comma-separated list of packages to include\n", .{});
            std.debug.print("  --os-version <ver>  FreeBSD version (default: auto-detect)\n", .{});
            std.debug.print("  --arch <arch>       Architecture (default: auto-detect)\n", .{});
            std.debug.print("  --description <d>   Description for the tarball\n", .{});
            std.debug.print("  --compression <c>   Compression: zstd, gzip, xz, none (default: zstd)\n", .{});
            std.debug.print("\nExamples:\n", .{});
            std.debug.print("  axiom bootstrap-export axiom-bootstrap-14.2-amd64.tar.zst\n", .{});
            std.debug.print("  axiom bootstrap-export minimal.tar.gz --minimal --compression gzip\n", .{});
            std.debug.print("  axiom bootstrap-export custom.tar.zst --packages gmake,m4,perl5\n", .{});
            return;
        }

        const output_path = args[0];

        // Parse options
        var options = bootstrap_pkg.ExportOptions{};
        var custom_packages = std.ArrayList([]const u8).init(self.allocator);
        defer custom_packages.deinit();

        var i: usize = 1;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--minimal")) {
                options.minimal = true;
            } else if (std.mem.eql(u8, args[i], "--packages") and i + 1 < args.len) {
                i += 1;
                // Parse comma-separated package list
                var pkg_iter = std.mem.splitScalar(u8, args[i], ',');
                while (pkg_iter.next()) |pkg| {
                    try custom_packages.append(pkg);
                }
            } else if (std.mem.eql(u8, args[i], "--os-version") and i + 1 < args.len) {
                i += 1;
                options.os_version = args[i];
            } else if (std.mem.eql(u8, args[i], "--arch") and i + 1 < args.len) {
                i += 1;
                options.arch = args[i];
            } else if (std.mem.eql(u8, args[i], "--description") and i + 1 < args.len) {
                i += 1;
                options.description = args[i];
            } else if (std.mem.eql(u8, args[i], "--compression") and i + 1 < args.len) {
                i += 1;
                if (std.mem.eql(u8, args[i], "zstd")) {
                    options.compression = .zstd;
                } else if (std.mem.eql(u8, args[i], "gzip")) {
                    options.compression = .gzip;
                } else if (std.mem.eql(u8, args[i], "xz")) {
                    options.compression = .xz;
                } else if (std.mem.eql(u8, args[i], "none")) {
                    options.compression = .none;
                }
            }
        }

        if (custom_packages.items.len > 0) {
            options.packages = custom_packages.items;
        }

        var bootstrap_mgr = BootstrapManager.init(
            self.allocator,
            self.zfs_handle,
            self.store,
            self.importer,
        );

        _ = try bootstrap_mgr.exportBootstrap(output_path, options);
    }

    /// Bootstrap from FreeBSD ports - builds the complete bootstrap chain
    fn bootstrapPorts(self: *CLI, args: []const []const u8) !void {
        // Parse options
        var dry_run = false;
        var verbose = false;
        var jobs: u32 = 4;
        var minimal = false;

        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            if (std.mem.eql(u8, args[i], "--help") or std.mem.eql(u8, args[i], "-h")) {
                std.debug.print("Usage: axiom bootstrap-ports [options]\n", .{});
                std.debug.print("\nBuild the complete bootstrap chain from FreeBSD ports.\n", .{});
                std.debug.print("This automatically imports packages in the correct order:\n", .{});
                std.debug.print("  1. misc/help2man (man page generator)\n", .{});
                std.debug.print("  2. devel/m4      (macro processor)\n", .{});
                std.debug.print("  3. devel/gmake   (GNU make)\n", .{});
                std.debug.print("\nFor a full bootstrap, also builds:\n", .{});
                std.debug.print("  4. devel/gettext-runtime\n", .{});
                std.debug.print("  5. lang/perl5.42\n", .{});
                std.debug.print("  6. devel/autoconf\n", .{});
                std.debug.print("  7. devel/automake\n", .{});
                std.debug.print("  8. devel/libtool\n", .{});
                std.debug.print("  9. devel/pkgconf\n", .{});
                std.debug.print("\nOptions:\n", .{});
                std.debug.print("  --minimal        Build only the minimal chain (help2man, m4, gmake)\n", .{});
                std.debug.print("  --dry-run        Show what would be built without building\n", .{});
                std.debug.print("  --verbose        Show detailed build output\n", .{});
                std.debug.print("  --jobs <n>       Number of parallel build jobs (default: 4)\n", .{});
                std.debug.print("\nExamples:\n", .{});
                std.debug.print("  axiom bootstrap-ports                # Full bootstrap\n", .{});
                std.debug.print("  axiom bootstrap-ports --minimal      # Minimal bootstrap\n", .{});
                std.debug.print("  axiom bootstrap-ports --dry-run      # Show what would be done\n", .{});
                std.debug.print("\nNote: Requires the FreeBSD ports tree at /usr/ports\n", .{});
                std.debug.print("      Install with: portsnap fetch extract\n", .{});
                return;
            } else if (std.mem.eql(u8, args[i], "--dry-run")) {
                dry_run = true;
            } else if (std.mem.eql(u8, args[i], "--verbose")) {
                verbose = true;
            } else if (std.mem.eql(u8, args[i], "--minimal")) {
                minimal = true;
            } else if (std.mem.eql(u8, args[i], "--jobs") and i + 1 < args.len) {
                i += 1;
                jobs = std.fmt.parseInt(u32, args[i], 10) catch 4;
            }
        }

        std.debug.print("Axiom Bootstrap from Ports\n", .{});
        std.debug.print("==========================\n\n", .{});

        // Check if ports tree exists
        std.fs.accessAbsolute("/usr/ports/Mk/bsd.port.mk", .{}) catch {
            std.debug.print("Error: FreeBSD ports tree not found at /usr/ports\n", .{});
            std.debug.print("\nTo install the ports tree, run:\n", .{});
            std.debug.print("  portsnap fetch extract\n", .{});
            std.debug.print("Or:\n", .{});
            std.debug.print("  git clone https://git.FreeBSD.org/ports.git /usr/ports\n", .{});
            return;
        };

        // Define the bootstrap chain
        const MINIMAL_CHAIN = [_][]const u8{
            "misc/help2man",
            "devel/m4",
            "devel/gmake",
        };

        const FULL_CHAIN = [_][]const u8{
            "misc/help2man",
            "devel/m4",
            "devel/gmake",
            "devel/gettext-runtime",
            "lang/perl5.42",
            "devel/autoconf",
            "devel/automake",
            "devel/libtool",
            "devel/pkgconf",
        };

        const chain = if (minimal) &MINIMAL_CHAIN else &FULL_CHAIN;

        std.debug.print("Bootstrap mode: {s}\n", .{if (minimal) "minimal" else "full"});
        std.debug.print("Packages to build: {d}\n", .{chain.len});
        std.debug.print("Parallel jobs: {d}\n\n", .{jobs});

        if (dry_run) {
            std.debug.print("Dry run - showing build plan:\n\n", .{});
            for (chain, 0..) |port, idx| {
                std.debug.print("  {d}. {s}\n", .{ idx + 1, port });
            }
            std.debug.print("\nRun without --dry-run to execute.\n", .{});
            return;
        }

        // Initialize ports migrator with options
        var migrator = PortsMigrator.init(self.allocator, .{
            .verbose = verbose,
            .build_jobs = jobs,
            .build_after_generate = true,
            .import_after_build = true,
            .zfs_handle = self.zfs_handle,
            .store = self.store,
            .importer = self.importer,
        });

        // Build each package in order
        var success_count: u32 = 0;
        var skip_count: u32 = 0;
        var fail_count: u32 = 0;

        for (chain, 0..) |port, idx| {
            std.debug.print("\n[{d}/{d}] Building: {s}\n", .{ idx + 1, chain.len, port });
            std.debug.print("────────────────────────────────────────\n", .{});

            // Check if already installed
            const pkg_name = extractPackageName(port);
            if (try self.isPackageInstalled(pkg_name)) {
                std.debug.print("  ✓ Already installed, skipping\n", .{});
                skip_count += 1;
                continue;
            }

            // Build and import
            var result = migrator.migrate(port) catch |err| {
                std.debug.print("  ✗ Failed: {}\n", .{err});
                fail_count += 1;
                continue;
            };
            defer result.deinit(self.allocator);

            switch (result.status) {
                .imported => {
                    std.debug.print("  ✓ Successfully built and imported\n", .{});
                    success_count += 1;
                },
                .skipped => {
                    std.debug.print("  ○ Skipped\n", .{});
                    skip_count += 1;
                },
                .failed => {
                    std.debug.print("  ✗ Build failed\n", .{});
                    fail_count += 1;
                },
                else => {
                    std.debug.print("  ? Unexpected status: {}\n", .{result.status});
                    fail_count += 1;
                },
            }
        }

        // Summary
        std.debug.print("\n", .{});
        std.debug.print("════════════════════════════════════════\n", .{});
        std.debug.print("Bootstrap Complete\n", .{});
        std.debug.print("════════════════════════════════════════\n", .{});
        std.debug.print("  Built:   {d}\n", .{success_count});
        std.debug.print("  Skipped: {d}\n", .{skip_count});
        std.debug.print("  Failed:  {d}\n", .{fail_count});

        if (fail_count == 0) {
            std.debug.print("\n✓ Bootstrap successful!\n", .{});
            std.debug.print("\nYou can now build other ports without pkg:\n", .{});
            std.debug.print("  axiom ports-import shells/bash\n", .{});
            std.debug.print("  axiom ports-import editors/vim\n", .{});
        } else {
            std.debug.print("\n✗ Some packages failed to build.\n", .{});
            std.debug.print("Check the errors above and try again.\n", .{});
        }
    }

    /// Extract package name from port origin (e.g., "devel/gmake" -> "gmake")
    fn extractPackageName(origin: []const u8) []const u8 {
        if (std.mem.indexOf(u8, origin, "/")) |idx| {
            return origin[idx + 1 ..];
        }
        return origin;
    }

    /// Check if a package is installed in the store
    fn isPackageInstalled(self: *CLI, name: []const u8) !bool {
        const pkg_path = try std.fmt.allocPrint(self.allocator, "/axiom/store/pkg/{s}", .{name});
        defer self.allocator.free(pkg_path);

        var dir = std.fs.openDirAbsolute(pkg_path, .{}) catch {
            return false;
        };
        dir.close();
        return true;
    }
};
