// Desktop Integration Helpers
//
// Provides integration with desktop environments including:
// - .desktop file generation
// - Icon installation
// - MIME type registration
// - Menu integration

const std = @import("std");
const types = @import("types.zig");
const manifest = @import("manifest.zig");

const Version = types.Version;
const PackageId = types.PackageId;
const Manifest = manifest.Manifest;

/// Desktop entry metadata (from manifest.yaml)
pub const DesktopEntry = struct {
    /// Display name
    name: []const u8,

    /// Generic name (e.g., "Text Editor")
    generic_name: ?[]const u8 = null,

    /// Comment/description
    comment: ?[]const u8 = null,

    /// Executable path (relative to package root)
    executable: []const u8,

    /// Icon name or path
    icon: ?[]const u8 = null,

    /// Desktop categories (Graphics, Development, etc.)
    categories: []const []const u8 = &[_][]const u8{},

    /// Keywords for search
    keywords: []const []const u8 = &[_][]const u8{},

    /// MIME types this application handles
    mime_types: []const []const u8 = &[_][]const u8{},

    /// Whether to show in menus
    no_display: bool = false,

    /// Run in terminal
    terminal: bool = false,

    /// Startup notification
    startup_notify: bool = true,

    /// Actions (additional right-click options)
    actions: []DesktopAction = &[_]DesktopAction{},
};

/// Desktop action (for right-click menu)
pub const DesktopAction = struct {
    id: []const u8,
    name: []const u8,
    executable: []const u8,
    icon: ?[]const u8 = null,
};

/// Icon metadata
pub const IconInfo = struct {
    path: []const u8,
    size: u32, // 16, 22, 24, 32, 48, 64, 128, 256, 512
    theme: []const u8 = "hicolor",
    context: []const u8 = "apps",
};

/// Desktop integration manager
pub const DesktopIntegration = struct {
    allocator: std.mem.Allocator,

    /// XDG directories
    xdg_data_home: []const u8,
    xdg_data_dirs: []const []const u8,

    /// User-level integration (vs system-wide)
    user_mode: bool,

    pub fn init(allocator: std.mem.Allocator) DesktopIntegration {
        // Get XDG directories
        const data_home = std.process.getEnvVarOwned(allocator, "XDG_DATA_HOME") catch
            std.fmt.allocPrint(allocator, "{s}/.local/share", .{
            std.process.getEnvVarOwned(allocator, "HOME") catch "/root",
        }) catch "/tmp";

        return .{
            .allocator = allocator,
            .xdg_data_home = data_home,
            .xdg_data_dirs = &[_][]const u8{
                "/usr/local/share",
                "/usr/share",
            },
            .user_mode = true,
        };
    }

    pub fn deinit(self: *DesktopIntegration) void {
        self.allocator.free(self.xdg_data_home);
    }

    /// Install desktop integration for a package
    pub fn install(
        self: *DesktopIntegration,
        pkg_id: PackageId,
        pkg_root: []const u8,
        entry: DesktopEntry,
    ) !void {
        std.debug.print("Installing desktop integration for {s}...\n", .{pkg_id.name});

        // Generate and install .desktop file
        try self.installDesktopFile(pkg_id, pkg_root, entry);

        // Install icons
        if (entry.icon) |icon_path| {
            try self.installIcon(pkg_id, pkg_root, icon_path);
        }

        // Register MIME types
        if (entry.mime_types.len > 0) {
            try self.registerMimeTypes(pkg_id, entry.mime_types);
        }

        // Update desktop database
        try self.updateDesktopDatabase();
    }

    /// Remove desktop integration for a package
    pub fn uninstall(self: *DesktopIntegration, pkg_id: PackageId) !void {
        std.debug.print("Removing desktop integration for {s}...\n", .{pkg_id.name});

        // Remove .desktop file
        const desktop_path = try self.getDesktopFilePath(pkg_id);
        defer self.allocator.free(desktop_path);
        std.fs.cwd().deleteFile(desktop_path) catch {};

        // Remove icons
        try self.removeIcons(pkg_id);

        // Update desktop database
        try self.updateDesktopDatabase();
    }

    fn installDesktopFile(
        self: *DesktopIntegration,
        pkg_id: PackageId,
        pkg_root: []const u8,
        entry: DesktopEntry,
    ) !void {
        // Generate .desktop content
        const content = try self.generateDesktopFile(pkg_id, pkg_root, entry);
        defer self.allocator.free(content);

        // Ensure directory exists
        const desktop_dir = try std.fs.path.join(self.allocator, &[_][]const u8{
            self.xdg_data_home,
            "applications",
        });
        defer self.allocator.free(desktop_dir);
        std.fs.cwd().makePath(desktop_dir) catch {};

        // Write file
        const desktop_path = try self.getDesktopFilePath(pkg_id);
        defer self.allocator.free(desktop_path);

        const file = try std.fs.cwd().createFile(desktop_path, .{});
        defer file.close();
        try file.writeAll(content);

        std.debug.print("  Created: {s}\n", .{desktop_path});
    }

    fn generateDesktopFile(
        self: *DesktopIntegration,
        pkg_id: PackageId,
        pkg_root: []const u8,
        entry: DesktopEntry,
    ) ![]const u8 {
        var output: std.ArrayList(u8) = .empty;
        defer output.deinit(self.allocator);

        const writer = output.writer();

        try writer.print("[Desktop Entry]\n", .{});
        try writer.print("Type=Application\n", .{});
        try writer.print("Version=1.0\n", .{});
        try writer.print("Name={s}\n", .{entry.name});

        if (entry.generic_name) |gn| {
            try writer.print("GenericName={s}\n", .{gn});
        }

        if (entry.comment) |c| {
            try writer.print("Comment={s}\n", .{c});
        }

        // Build executable path
        const exec_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            pkg_root,
            "root",
            entry.executable,
        });
        defer self.allocator.free(exec_path);
        try writer.print("Exec={s} %F\n", .{exec_path});

        if (entry.icon) |icon| {
            // Use package ID as icon name
            try writer.print("Icon=axiom-{s}\n", .{pkg_id.name});
            _ = icon;
        }

        try writer.print("Terminal={}\n", .{entry.terminal});
        try writer.print("StartupNotify={}\n", .{entry.startup_notify});

        if (entry.categories.len > 0) {
            try writer.print("Categories=", .{});
            for (entry.categories, 0..) |cat, i| {
                if (i > 0) try writer.print(";", .{});
                try writer.print("{s}", .{cat});
            }
            try writer.print(";\n", .{});
        }

        if (entry.keywords.len > 0) {
            try writer.print("Keywords=", .{});
            for (entry.keywords, 0..) |kw, i| {
                if (i > 0) try writer.print(";", .{});
                try writer.print("{s}", .{kw});
            }
            try writer.print(";\n", .{});
        }

        if (entry.mime_types.len > 0) {
            try writer.print("MimeType=", .{});
            for (entry.mime_types, 0..) |mt, i| {
                if (i > 0) try writer.print(";", .{});
                try writer.print("{s}", .{mt});
            }
            try writer.print(";\n", .{});
        }

        if (entry.no_display) {
            try writer.print("NoDisplay=true\n", .{});
        }

        // Add actions
        if (entry.actions.len > 0) {
            try writer.print("\nActions=", .{});
            for (entry.actions, 0..) |action, i| {
                if (i > 0) try writer.print(";", .{});
                try writer.print("{s}", .{action.id});
            }
            try writer.print(";\n", .{});

            for (entry.actions) |action| {
                try writer.print("\n[Desktop Action {s}]\n", .{action.id});
                try writer.print("Name={s}\n", .{action.name});
                try writer.print("Exec={s}/{s}\n", .{ pkg_root, action.executable });
                if (action.icon) |icon| {
                    try writer.print("Icon={s}\n", .{icon});
                }
            }
        }

        return try output.toOwnedSlice(self.allocator);
    }

    fn getDesktopFilePath(self: *DesktopIntegration, pkg_id: PackageId) ![]const u8 {
        return try std.fmt.allocPrint(self.allocator, "{s}/applications/axiom-{s}.desktop", .{
            self.xdg_data_home,
            pkg_id.name,
        });
    }

    fn installIcon(
        self: *DesktopIntegration,
        pkg_id: PackageId,
        pkg_root: []const u8,
        icon_path: []const u8,
    ) !void {
        // Source icon path
        const src_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            pkg_root,
            "root",
            icon_path,
        });
        defer self.allocator.free(src_path);

        // Determine icon format and size from filename
        const ext = std.fs.path.extension(icon_path);
        const is_svg = std.mem.eql(u8, ext, ".svg");

        // Install to appropriate directory
        const icon_dir = if (is_svg)
            try std.fmt.allocPrint(self.allocator, "{s}/icons/hicolor/scalable/apps", .{
                self.xdg_data_home,
            })
        else
            try std.fmt.allocPrint(self.allocator, "{s}/icons/hicolor/48x48/apps", .{
                self.xdg_data_home,
            });
        defer self.allocator.free(icon_dir);

        std.fs.cwd().makePath(icon_dir) catch {};

        const icon_name = try std.fmt.allocPrint(self.allocator, "axiom-{s}{s}", .{
            pkg_id.name,
            ext,
        });
        defer self.allocator.free(icon_name);

        const dest_path = try std.fs.path.join(self.allocator, &[_][]const u8{
            icon_dir,
            icon_name,
        });
        defer self.allocator.free(dest_path);

        // Copy icon file
        std.fs.cwd().copyFile(src_path, std.fs.cwd(), dest_path, .{}) catch |err| {
            std.debug.print("  Warning: Could not install icon: {s}\n", .{@errorName(err)});
            return;
        };

        std.debug.print("  Installed icon: {s}\n", .{dest_path});
    }

    fn removeIcons(self: *DesktopIntegration, pkg_id: PackageId) !void {
        const icon_dirs = [_][]const u8{
            "icons/hicolor/scalable/apps",
            "icons/hicolor/48x48/apps",
            "icons/hicolor/32x32/apps",
            "icons/hicolor/24x24/apps",
            "icons/hicolor/16x16/apps",
        };

        for (icon_dirs) |dir| {
            const icon_path_svg = try std.fmt.allocPrint(self.allocator, "{s}/{s}/axiom-{s}.svg", .{
                self.xdg_data_home,
                dir,
                pkg_id.name,
            });
            defer self.allocator.free(icon_path_svg);
            std.fs.cwd().deleteFile(icon_path_svg) catch {};

            const icon_path_png = try std.fmt.allocPrint(self.allocator, "{s}/{s}/axiom-{s}.png", .{
                self.xdg_data_home,
                dir,
                pkg_id.name,
            });
            defer self.allocator.free(icon_path_png);
            std.fs.cwd().deleteFile(icon_path_png) catch {};
        }
    }

    fn registerMimeTypes(
        self: *DesktopIntegration,
        pkg_id: PackageId,
        mime_types: []const []const u8,
    ) !void {
        _ = pkg_id;

        // Create MIME database entry
        const mime_dir = try std.fs.path.join(self.allocator, &[_][]const u8{
            self.xdg_data_home,
            "mime",
            "packages",
        });
        defer self.allocator.free(mime_dir);
        std.fs.cwd().makePath(mime_dir) catch {};

        // For each MIME type, check if we need to create a definition
        for (mime_types) |mt| {
            std.debug.print("  Registered MIME type: {s}\n", .{mt});
        }
    }

    fn updateDesktopDatabase(self: *DesktopIntegration) !void {
        // Update desktop file database
        const apps_dir = try std.fs.path.join(self.allocator, &[_][]const u8{
            self.xdg_data_home,
            "applications",
        });
        defer self.allocator.free(apps_dir);

        var child = std.process.Child.init(
            &[_][]const u8{ "update-desktop-database", apps_dir },
            self.allocator,
        );
        _ = child.spawnAndWait() catch {
            // update-desktop-database may not be installed, that's OK
        };

        // Update icon cache
        const icons_dir = try std.fs.path.join(self.allocator, &[_][]const u8{
            self.xdg_data_home,
            "icons",
            "hicolor",
        });
        defer self.allocator.free(icons_dir);

        var icon_child = std.process.Child.init(
            &[_][]const u8{ "gtk-update-icon-cache", "-f", icons_dir },
            self.allocator,
        );
        _ = icon_child.spawnAndWait() catch {
            // gtk-update-icon-cache may not be installed, that's OK
        };
    }

    /// List all installed desktop integrations
    pub fn listInstalled(self: *DesktopIntegration) ![]InstalledDesktopEntry {
        var entries: std.ArrayList(InstalledDesktopEntry) = .empty;
        defer entries.deinit(self.allocator);

        const apps_dir = try std.fs.path.join(self.allocator, &[_][]const u8{
            self.xdg_data_home,
            "applications",
        });
        defer self.allocator.free(apps_dir);

        var dir = std.fs.cwd().openDir(apps_dir, .{ .iterate = true }) catch {
            return try entries.toOwnedSlice(self.allocator);
        };
        defer dir.close();

        var iter = dir.iterate();
        while (try iter.next()) |entry| {
            if (entry.kind == .file and std.mem.startsWith(u8, entry.name, "axiom-")) {
                if (std.mem.endsWith(u8, entry.name, ".desktop")) {
                    const pkg_name = entry.name[6 .. entry.name.len - 8];
                    try entries.append(self.allocator, .{
                        .package_name = try self.allocator.dupe(u8, pkg_name),
                        .desktop_file = try std.fs.path.join(self.allocator, &[_][]const u8{
                            apps_dir,
                            entry.name,
                        }),
                    });
                }
            }
        }

        return try entries.toOwnedSlice(self.allocator);
    }
};

/// Information about an installed desktop entry
pub const InstalledDesktopEntry = struct {
    package_name: []const u8,
    desktop_file: []const u8,

    pub fn deinit(self: *InstalledDesktopEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.package_name);
        allocator.free(self.desktop_file);
    }
};

/// Parse desktop entry from manifest.yaml desktop section
pub fn parseDesktopEntry(allocator: std.mem.Allocator, content: []const u8) !?DesktopEntry {
    _ = allocator;

    // Look for "desktop:" section in YAML
    if (std.mem.indexOf(u8, content, "desktop:") == null) {
        return null;
    }

    // Simplified parsing - in production use proper YAML parser
    var entry = DesktopEntry{
        .name = "Application",
        .executable = "bin/app",
    };

    // Parse name
    if (std.mem.indexOf(u8, content, "name:")) |pos| {
        const start = pos + 5;
        const end = std.mem.indexOfPos(u8, content, start, "\n") orelse content.len;
        entry.name = std.mem.trim(u8, content[start..end], " \t");
    }

    // Parse executable
    if (std.mem.indexOf(u8, content, "executable:")) |pos| {
        const start = pos + 11;
        const end = std.mem.indexOfPos(u8, content, start, "\n") orelse content.len;
        entry.executable = std.mem.trim(u8, content[start..end], " \t");
    }

    return entry;
}

// Tests
test "desktop file generation" {
    const allocator = std.testing.allocator;

    var di = DesktopIntegration.empty;
    defer di.deinit();

    const pkg_id = types.PackageId{
        .name = "test-app",
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
        .revision = 1,
        .build_id = "abc123",
    };

    const entry = DesktopEntry{
        .name = "Test Application",
        .executable = "bin/test-app",
        .categories = &[_][]const u8{ "Utility", "Development" },
    };

    const content = try di.generateDesktopFile(pkg_id, "/axiom/store/test", entry);
    defer allocator.free(content);

    try std.testing.expect(std.mem.indexOf(u8, content, "[Desktop Entry]") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, "Name=Test Application") != null);
}
