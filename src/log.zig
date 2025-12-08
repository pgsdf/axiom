const std = @import("std");

/// Log levels in order of severity
pub const Level = enum {
    debug,
    info,
    warn,
    err,

    pub fn toString(self: Level) []const u8 {
        return switch (self) {
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .err => "ERROR",
        };
    }
};

/// Global log configuration
pub const Config = struct {
    /// Minimum level to output (messages below this level are suppressed)
    min_level: Level = .info,
    /// Whether to include timestamps in output
    show_timestamps: bool = true,
    /// Whether logging is enabled at all
    enabled: bool = true,
    /// Output writer (defaults to stderr)
    writer: std.fs.File.Writer = std.io.getStdErr().writer(),
};

/// Global configuration instance
var global_config: Config = .{};

/// Initialize the logger with custom configuration
pub fn init(config: Config) void {
    global_config = config;
}

/// Set the minimum log level
pub fn setLevel(level: Level) void {
    global_config.min_level = level;
}

/// Enable or disable logging
pub fn setEnabled(enabled: bool) void {
    global_config.enabled = enabled;
}

/// Core logging function
fn logImpl(level: Level, comptime fmt: []const u8, args: anytype) void {
    if (!global_config.enabled) return;
    if (@intFromEnum(level) < @intFromEnum(global_config.min_level)) return;

    const writer = global_config.writer;

    // Write timestamp if enabled
    if (global_config.show_timestamps) {
        const timestamp = std.time.timestamp();
        writer.print("[{d}] ", .{timestamp}) catch return;
    }

    // Write level
    writer.print("[{s}] ", .{level.toString()}) catch return;

    // Write message
    writer.print(fmt, args) catch return;
    writer.writeByte('\n') catch return;
}

/// Log a debug message
pub fn debug(comptime fmt: []const u8, args: anytype) void {
    logImpl(.debug, fmt, args);
}

/// Log an info message
pub fn info(comptime fmt: []const u8, args: anytype) void {
    logImpl(.info, fmt, args);
}

/// Log a warning message
pub fn warn(comptime fmt: []const u8, args: anytype) void {
    logImpl(.warn, fmt, args);
}

/// Log an error message
pub fn err(comptime fmt: []const u8, args: anytype) void {
    logImpl(.err, fmt, args);
}

// =============================================================================
// Scoped Logger - for module-specific logging with prefixes
// =============================================================================

/// Create a scoped logger with a module prefix
pub fn scoped(comptime scope: []const u8) type {
    return struct {
        pub fn debug(comptime fmt: []const u8, args: anytype) void {
            logImpl(.debug, "[" ++ scope ++ "] " ++ fmt, args);
        }

        pub fn info(comptime fmt: []const u8, args: anytype) void {
            logImpl(.info, "[" ++ scope ++ "] " ++ fmt, args);
        }

        pub fn warn(comptime fmt: []const u8, args: anytype) void {
            logImpl(.warn, "[" ++ scope ++ "] " ++ fmt, args);
        }

        pub fn err(comptime fmt: []const u8, args: anytype) void {
            logImpl(.err, "[" ++ scope ++ "] " ++ fmt, args);
        }
    };
}

// =============================================================================
// Tests
// =============================================================================

test "log levels" {
    // Test level ordering
    try std.testing.expect(@intFromEnum(Level.debug) < @intFromEnum(Level.info));
    try std.testing.expect(@intFromEnum(Level.info) < @intFromEnum(Level.warn));
    try std.testing.expect(@intFromEnum(Level.warn) < @intFromEnum(Level.err));
}

test "level toString" {
    try std.testing.expectEqualStrings("DEBUG", Level.debug.toString());
    try std.testing.expectEqualStrings("INFO", Level.info.toString());
    try std.testing.expectEqualStrings("WARN", Level.warn.toString());
    try std.testing.expectEqualStrings("ERROR", Level.err.toString());
}
