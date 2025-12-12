// =============================================================================
// Module Interfaces - Phase 56: Module Decoupling
// =============================================================================
//
// This module defines contracts (interfaces) for Axiom's core components,
// enabling dependency injection, testing with mocks, and reduced coupling.
//
// ## Architecture
//
// ┌─────────────────────────────────────────┐
// │              CLI Layer                   │
// │  (cli.zig - thin, uses interfaces)      │
// └─────────────────┬───────────────────────┘
//                   │ depends on
// ┌─────────────────▼───────────────────────┐
// │           Interface Layer                │
// │  (interfaces.zig - contracts)           │
// └─────────────────┬───────────────────────┘
//                   │ implemented by
// ┌─────────────────▼───────────────────────┐
// │         Implementation Layer             │
// │  (store.zig, resolver.zig, etc.)        │
// └─────────────────┬───────────────────────┘
//                   │ depends on
// ┌─────────────────▼───────────────────────┐
// │          Foundation Layer                │
// │  (zfs.zig, errors.zig, validation.zig)  │
// └─────────────────────────────────────────┘
//
// ## Usage
//
// Instead of directly importing concrete implementations:
//   const store = @import("store.zig");
//   var pkg_store = store.PackageStore.init(...);
//
// Use interfaces for testability and decoupling:
//   const interfaces = @import("interfaces.zig");
//   fn processPackages(store: interfaces.PackageStore) !void { ... }
//
// =============================================================================

const std = @import("std");
const types = @import("types.zig");

const PackageId = types.PackageId;
const Version = types.Version;

// =============================================================================
// Package Store Interface
// =============================================================================

/// Interface for package storage operations.
/// Implementations: store.PackageStore (real), MockPackageStore (testing)
pub const PackageStore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Get a package by its ID
        getPackage: *const fn (ctx: *anyopaque, id: PackageId) anyerror!?PackageInfo,
        /// List all packages in the store
        listPackages: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator) anyerror![]PackageId,
        /// Check if a package exists
        packageExists: *const fn (ctx: *anyopaque, id: PackageId) bool,
        /// Get the store path
        getStorePath: *const fn (ctx: *anyopaque) []const u8,
    };

    /// Package information returned by the store
    pub const PackageInfo = struct {
        id: PackageId,
        path: []const u8,
        size: u64,
        dependencies: []const Dependency,

        pub const Dependency = struct {
            name: []const u8,
            constraint: ?[]const u8,
        };
    };

    pub fn getPackage(self: PackageStore, id: PackageId) !?PackageInfo {
        return self.vtable.getPackage(self.ptr, id);
    }

    pub fn listPackages(self: PackageStore, allocator: std.mem.Allocator) ![]PackageId {
        return self.vtable.listPackages(self.ptr, allocator);
    }

    pub fn packageExists(self: PackageStore, id: PackageId) bool {
        return self.vtable.packageExists(self.ptr, id);
    }

    pub fn getStorePath(self: PackageStore) []const u8 {
        return self.vtable.getStorePath(self.ptr);
    }
};

// =============================================================================
// Profile Manager Interface
// =============================================================================

/// Interface for profile management operations.
/// Implementations: profile.ProfileManager (real), MockProfileManager (testing)
pub const ProfileManager = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// List all profiles
        listProfiles: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator) anyerror![]ProfileInfo,
        /// Get current active profile
        getCurrentProfile: *const fn (ctx: *anyopaque) anyerror!?[]const u8,
        /// Get packages in a profile
        getProfilePackages: *const fn (ctx: *anyopaque, name: []const u8, allocator: std.mem.Allocator) anyerror![]PackageId,
    };

    pub const ProfileInfo = struct {
        name: []const u8,
        is_active: bool,
        package_count: u32,
    };

    pub fn listProfiles(self: ProfileManager, allocator: std.mem.Allocator) ![]ProfileInfo {
        return self.vtable.listProfiles(self.ptr, allocator);
    }

    pub fn getCurrentProfile(self: ProfileManager) !?[]const u8 {
        return self.vtable.getCurrentProfile(self.ptr);
    }

    pub fn getProfilePackages(self: ProfileManager, name: []const u8, allocator: std.mem.Allocator) ![]PackageId {
        return self.vtable.getProfilePackages(self.ptr, name, allocator);
    }
};

// =============================================================================
// Resolver Interface
// =============================================================================

/// Interface for dependency resolution.
/// Implementations: resolver.Resolver (real), MockResolver (testing)
pub const Resolver = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Resolve dependencies for a set of package requests
        resolve: *const fn (ctx: *anyopaque, requests: []const Request, allocator: std.mem.Allocator) anyerror!Resolution,
    };

    pub const Request = struct {
        name: []const u8,
        constraint: ?[]const u8,
    };

    pub const Resolution = struct {
        packages: []const PackageId,
        conflicts: []const Conflict,

        pub const Conflict = struct {
            package_a: []const u8,
            package_b: []const u8,
            reason: []const u8,
        };
    };

    pub fn resolve(self: Resolver, requests: []const Request, allocator: std.mem.Allocator) !Resolution {
        return self.vtable.resolve(self.ptr, requests, allocator);
    }
};

// =============================================================================
// Output Interface
// =============================================================================

/// Interface for CLI output, enabling testing without stdout.
/// Implementations: StdOutput (real), BufferedOutput (testing)
pub const Output = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Write a line of output
        writeLine: *const fn (ctx: *anyopaque, line: []const u8) anyerror!void,
        /// Write formatted output
        print: *const fn (ctx: *anyopaque, comptime fmt: []const u8, args: anytype) anyerror!void,
        /// Write an error message
        writeError: *const fn (ctx: *anyopaque, msg: []const u8) anyerror!void,
    };

    pub fn writeLine(self: Output, line: []const u8) !void {
        return self.vtable.writeLine(self.ptr, line);
    }

    pub fn writeError(self: Output, msg: []const u8) !void {
        return self.vtable.writeError(self.ptr, msg);
    }
};

// =============================================================================
// Standard Output Implementation
// =============================================================================

/// Standard output implementation using stdout/stderr
pub const StdOutput = struct {
    stdout: std.fs.File.Writer,
    stderr: std.fs.File.Writer,

    pub fn init() StdOutput {
        return .{
            .stdout = std.io.getStdOut().writer(),
            .stderr = std.io.getStdErr().writer(),
        };
    }

    pub fn writeLine(ctx: *anyopaque, line: []const u8) !void {
        const self: *StdOutput = @ptrCast(@alignCast(ctx));
        try self.stdout.writeAll(line);
        try self.stdout.writeAll("\n");
    }

    pub fn writeError(ctx: *anyopaque, msg: []const u8) !void {
        const self: *StdOutput = @ptrCast(@alignCast(ctx));
        try self.stderr.writeAll("error: ");
        try self.stderr.writeAll(msg);
        try self.stderr.writeAll("\n");
    }

    pub fn asInterface(self: *StdOutput) Output {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable = Output.VTable{
        .writeLine = writeLine,
        .print = undefined, // TODO: implement with formatting
        .writeError = writeError,
    };
};

// =============================================================================
// Mock Implementations for Testing
// =============================================================================

/// Mock package store for testing
pub const MockPackageStore = struct {
    packages: std.StringHashMap(PackageStore.PackageInfo),
    store_path: []const u8,

    pub fn init(allocator: std.mem.Allocator) MockPackageStore {
        return .{
            .packages = std.StringHashMap(PackageStore.PackageInfo).init(allocator),
            .store_path = "/mock/store",
        };
    }

    pub fn deinit(self: *MockPackageStore) void {
        self.packages.deinit();
    }

    pub fn addPackage(self: *MockPackageStore, id: PackageId, info: PackageStore.PackageInfo) !void {
        try self.packages.put(id.name, info);
    }

    fn getPackage(ctx: *anyopaque, id: PackageId) anyerror!?PackageStore.PackageInfo {
        const self: *MockPackageStore = @ptrCast(@alignCast(ctx));
        return self.packages.get(id.name);
    }

    fn listPackages(ctx: *anyopaque, allocator: std.mem.Allocator) anyerror![]PackageId {
        const self: *MockPackageStore = @ptrCast(@alignCast(ctx));
        var result = std.ArrayList(PackageId).init(allocator);
        var iter = self.packages.iterator();
        while (iter.next()) |entry| {
            try result.append(entry.value_ptr.id);
        }
        return result.toOwnedSlice();
    }

    fn packageExists(ctx: *anyopaque, id: PackageId) bool {
        const self: *MockPackageStore = @ptrCast(@alignCast(ctx));
        return self.packages.contains(id.name);
    }

    fn getStorePath(ctx: *anyopaque) []const u8 {
        const self: *MockPackageStore = @ptrCast(@alignCast(ctx));
        return self.store_path;
    }

    pub fn asInterface(self: *MockPackageStore) PackageStore {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable = PackageStore.VTable{
        .getPackage = getPackage,
        .listPackages = listPackages,
        .packageExists = packageExists,
        .getStorePath = getStorePath,
    };
};

/// Buffered output for testing
pub const BufferedOutput = struct {
    lines: std.ArrayList([]const u8),
    errors: std.ArrayList([]const u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) BufferedOutput {
        return .{
            .lines = std.ArrayList([]const u8).init(allocator),
            .errors = std.ArrayList([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BufferedOutput) void {
        for (self.lines.items) |line| {
            self.allocator.free(line);
        }
        self.lines.deinit();
        for (self.errors.items) |err| {
            self.allocator.free(err);
        }
        self.errors.deinit();
    }

    fn writeLine(ctx: *anyopaque, line: []const u8) anyerror!void {
        const self: *BufferedOutput = @ptrCast(@alignCast(ctx));
        const copy = try self.allocator.dupe(u8, line);
        try self.lines.append(copy);
    }

    fn writeError(ctx: *anyopaque, msg: []const u8) anyerror!void {
        const self: *BufferedOutput = @ptrCast(@alignCast(ctx));
        const copy = try self.allocator.dupe(u8, msg);
        try self.errors.append(copy);
    }

    pub fn asInterface(self: *BufferedOutput) Output {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable = Output.VTable{
        .writeLine = writeLine,
        .print = undefined,
        .writeError = writeError,
    };
};

// =============================================================================
// CLI Context - Dependency Injection Container
// =============================================================================

/// Context for CLI operations, providing dependency injection.
/// This allows the CLI to be tested with mock implementations.
pub const CliContext = struct {
    allocator: std.mem.Allocator,
    store: ?PackageStore = null,
    profile_manager: ?ProfileManager = null,
    resolver: ?Resolver = null,
    output: Output,

    /// Create a context with standard output
    pub fn init(allocator: std.mem.Allocator, output: Output) CliContext {
        return .{
            .allocator = allocator,
            .output = output,
        };
    }

    /// Create a context for testing with buffered output
    pub fn initForTesting(allocator: std.mem.Allocator, buffered: *BufferedOutput) CliContext {
        return .{
            .allocator = allocator,
            .output = buffered.asInterface(),
        };
    }
};

// =============================================================================
// Tests
// =============================================================================

test "MockPackageStore basic operations" {
    const allocator = std.testing.allocator;
    var mock = MockPackageStore.init(allocator);
    defer mock.deinit();

    const id = PackageId{
        .name = "test-pkg",
        .version = Version{ .major = 1, .minor = 0, .patch = 0 },
        .revision = 1,
        .build_id = "abc123",
    };

    try mock.addPackage(id, .{
        .id = id,
        .path = "/mock/store/test-pkg",
        .size = 1024,
        .dependencies = &[_]PackageStore.PackageInfo.Dependency{},
    });

    const store_if = mock.asInterface();
    try std.testing.expect(store_if.packageExists(id));

    const info = try store_if.getPackage(id);
    try std.testing.expect(info != null);
    try std.testing.expectEqualStrings("/mock/store/test-pkg", info.?.path);
}

test "BufferedOutput captures output" {
    const allocator = std.testing.allocator;
    var buffered = BufferedOutput.init(allocator);
    defer buffered.deinit();

    const output = buffered.asInterface();
    try output.writeLine("Hello, World!");
    try output.writeError("Something went wrong");

    try std.testing.expectEqual(@as(usize, 1), buffered.lines.items.len);
    try std.testing.expectEqualStrings("Hello, World!", buffered.lines.items[0]);
    try std.testing.expectEqual(@as(usize, 1), buffered.errors.items.len);
    try std.testing.expectEqualStrings("Something went wrong", buffered.errors.items[0]);
}

test "CliContext initialization" {
    const allocator = std.testing.allocator;
    var buffered = BufferedOutput.init(allocator);
    defer buffered.deinit();

    const ctx = CliContext.initForTesting(allocator, &buffered);
    try std.testing.expect(ctx.store == null);
    try std.testing.expect(ctx.profile_manager == null);
}
