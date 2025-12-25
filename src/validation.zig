// ============================================================================
// Phase 53: Input Validation Framework
// ============================================================================
//
// This module provides comprehensive input validation for all external data
// including URLs, JSON, YAML, paths, and numeric values.
//
// Usage:
//   const validation = @import("validation.zig");
//
//   // URL validation
//   const result = validation.UrlValidator.validate(url);
//   if (!result.valid) return error.InvalidUrl;
//
//   // JSON escaping
//   const escaped = try validation.escapeJsonString(allocator, input);
//
//   // Numeric bounds
//   const size = try validation.parseSize(input, .{ .max = 1024 * 1024 * 1024 });
//

const std = @import("std");
const Allocator = std.mem.Allocator;

// ============================================================================
// URL Validation
// ============================================================================

pub const UrlValidator = struct {
    pub const Scheme = enum {
        http,
        https,
        file,
        unknown,
    };

    pub const ValidationResult = struct {
        valid: bool,
        scheme: Scheme,
        host: ?[]const u8,
        port: ?u16,
        path: ?[]const u8,
        query: ?[]const u8,
        error_message: ?[]const u8,

        pub fn format(
            self: ValidationResult,
            writer: anytype,
        ) !void {
            if (self.valid) {
                try writer.print("URL(scheme={s}, host={s}, port={?}, path={s})", .{
                    @tagName(self.scheme),
                    self.host orelse "<none>",
                    self.port,
                    self.path orelse "/",
                });
            } else {
                try writer.print("InvalidURL({s})", .{self.error_message orelse "unknown error"});
            }
        }
    };

    /// Validate a URL string and extract its components
    pub fn validate(url: []const u8) ValidationResult {
        if (url.len == 0) {
            return invalidResult("Empty URL");
        }

        // Check for null bytes
        if (std.mem.indexOfScalar(u8, url, 0) != null) {
            return invalidResult("URL contains null byte");
        }

        // Check for control characters
        for (url) |c| {
            if (c < 0x20 and c != '\t') {
                return invalidResult("URL contains control character");
            }
        }

        // Parse scheme
        const scheme_end = std.mem.indexOf(u8, url, "://") orelse {
            return invalidResult("Missing scheme (expected http:// or https://)");
        };

        const scheme_str = url[0..scheme_end];
        const scheme: Scheme = if (std.mem.eql(u8, scheme_str, "http"))
            .http
        else if (std.mem.eql(u8, scheme_str, "https"))
            .https
        else if (std.mem.eql(u8, scheme_str, "file"))
            .file
        else
            return invalidResult("Unsupported scheme (expected http, https, or file)");

        const authority_start = scheme_end + 3;
        if (authority_start >= url.len) {
            return invalidResult("Missing host");
        }

        // For file:// URLs, the rest is the path
        if (scheme == .file) {
            const path = url[authority_start..];
            if (!isValidPath(path)) {
                return invalidResult("Invalid path in file URL");
            }
            return .{
                .valid = true,
                .scheme = scheme,
                .host = null,
                .port = null,
                .path = path,
                .query = null,
                .error_message = null,
            };
        }

        // Find path start (first / after authority)
        const path_start = blk: {
            var i = authority_start;
            while (i < url.len) : (i += 1) {
                if (url[i] == '/') break :blk i;
                if (url[i] == '?') break :blk i; // Query without path
            }
            break :blk url.len;
        };

        const authority = url[authority_start..path_start];

        // Parse host and port from authority
        var host: []const u8 = undefined;
        var port: ?u16 = null;

        // Check for @ (userinfo) - we don't support it but should reject cleanly
        if (std.mem.indexOf(u8, authority, "@") != null) {
            return invalidResult("Userinfo in URL not supported");
        }

        // Check for IPv6 address [...]
        if (authority.len > 0 and authority[0] == '[') {
            const bracket_end = std.mem.indexOf(u8, authority, "]") orelse {
                return invalidResult("Unterminated IPv6 address");
            };
            host = authority[0 .. bracket_end + 1];

            // Check for port after ]
            if (bracket_end + 1 < authority.len) {
                if (authority[bracket_end + 1] == ':') {
                    const port_str = authority[bracket_end + 2 ..];
                    port = std.fmt.parseInt(u16, port_str, 10) catch {
                        return invalidResult("Invalid port number");
                    };
                    if (port.? == 0) {
                        return invalidResult("Port 0 is not allowed");
                    }
                } else {
                    return invalidResult("Invalid character after IPv6 address");
                }
            }
        } else {
            // Regular host:port parsing
            if (std.mem.lastIndexOf(u8, authority, ":")) |colon_pos| {
                host = authority[0..colon_pos];
                const port_str = authority[colon_pos + 1 ..];
                if (port_str.len > 0) {
                    port = std.fmt.parseInt(u16, port_str, 10) catch {
                        return invalidResult("Invalid port number");
                    };
                    if (port.? == 0) {
                        return invalidResult("Port 0 is not allowed");
                    }
                }
            } else {
                host = authority;
            }
        }

        // Validate host
        if (host.len == 0) {
            return invalidResult("Empty host");
        }

        if (!isValidHost(host)) {
            return invalidResult("Invalid host name");
        }

        // Parse path and query
        var path: ?[]const u8 = null;
        var query: ?[]const u8 = null;

        if (path_start < url.len) {
            const query_start = std.mem.indexOf(u8, url[path_start..], "?");
            if (query_start) |qs| {
                path = url[path_start .. path_start + qs];
                query = url[path_start + qs + 1 ..];
            } else {
                path = url[path_start..];
            }

            // Validate path - check for traversal
            if (path) |p| {
                if (!isValidPath(p)) {
                    return invalidResult("Invalid or unsafe path (traversal detected)");
                }
            }
        }

        return .{
            .valid = true,
            .scheme = scheme,
            .host = host,
            .port = port,
            .path = path,
            .query = query,
            .error_message = null,
        };
    }

    /// Check if a host string is valid
    fn isValidHost(host: []const u8) bool {
        if (host.len == 0) return false;

        // IPv6 addresses are enclosed in brackets
        if (host[0] == '[') {
            if (host.len < 4 or host[host.len - 1] != ']') return false;
            // Basic IPv6 validation - contains only hex digits and colons
            for (host[1 .. host.len - 1]) |c| {
                const valid = switch (c) {
                    '0'...'9', 'a'...'f', 'A'...'F', ':' => true,
                    else => false,
                };
                if (!valid) return false;
            }
            return true;
        }

        // Regular hostname/IPv4 validation
        for (host) |c| {
            const valid = switch (c) {
                'a'...'z', 'A'...'Z', '0'...'9' => true,
                '-', '.', '_' => true,
                else => false,
            };
            if (!valid) return false;
        }

        // Hostname shouldn't start or end with hyphen or dot
        if (host[0] == '-' or host[0] == '.') return false;
        if (host[host.len - 1] == '-' or host[host.len - 1] == '.') return false;

        return true;
    }

    /// Check if a path is valid and doesn't contain traversal
    fn isValidPath(path: []const u8) bool {
        // Check for path traversal attempts
        if (std.mem.indexOf(u8, path, "..") != null) {
            return false;
        }

        // Check for null bytes
        if (std.mem.indexOfScalar(u8, path, 0) != null) {
            return false;
        }

        // Check for control characters
        for (path) |c| {
            if (c < 0x20 and c != '\t') {
                return false;
            }
        }

        return true;
    }

    fn invalidResult(message: []const u8) ValidationResult {
        return .{
            .valid = false,
            .scheme = .unknown,
            .host = null,
            .port = null,
            .path = null,
            .query = null,
            .error_message = message,
        };
    }
};

// ============================================================================
// JSON String Escaping
// ============================================================================

/// Escape a string for safe inclusion in JSON
pub fn escapeJsonString(_: Allocator, input: []const u8) ![]const u8 {
    var result = std.ArrayList(u8).empty;
    errdefer result.deinit();

    for (input) |c| {
        switch (c) {
            '"' => try result.appendSlice("\\\""),
            '\\' => try result.appendSlice("\\\\"),
            '\n' => try result.appendSlice("\\n"),
            '\r' => try result.appendSlice("\\r"),
            '\t' => try result.appendSlice("\\t"),
            0x08 => try result.appendSlice("\\b"), // backspace
            0x0C => try result.appendSlice("\\f"), // form feed
            else => {
                if (c < 0x20) {
                    // Other control characters - use \uXXXX notation
                    try result.writer().print("\\u{x:0>4}", .{c});
                } else {
                    try result.append(c);
                }
            },
        }
    }

    return result.toOwnedSlice();
}

/// Write a JSON-escaped string directly to a writer
pub fn writeJsonEscaped(writer: anytype, input: []const u8) !void {
    for (input) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            0x08 => try writer.writeAll("\\b"),
            0x0C => try writer.writeAll("\\f"),
            else => {
                if (c < 0x20) {
                    try writer.print("\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
}

// ============================================================================
// Numeric Bounds Checking
// ============================================================================

pub const SizeParseOptions = struct {
    /// Minimum allowed value (default: 0)
    min: u64 = 0,
    /// Maximum allowed value (default: max u64)
    max: u64 = std.math.maxInt(u64),
    /// Allow size suffixes (K, M, G, T)
    allow_suffixes: bool = true,
    /// Default unit if no suffix (1 = bytes)
    default_unit: u64 = 1,
};

pub const SizeParseError = error{
    EmptyInput,
    InvalidCharacter,
    Overflow,
    BelowMinimum,
    AboveMaximum,
    InvalidSuffix,
};

/// Parse a size string like "100M" or "2G" with bounds checking
pub fn parseSize(input: []const u8, options: SizeParseOptions) SizeParseError!u64 {
    if (input.len == 0) {
        return SizeParseError.EmptyInput;
    }

    var end = input.len;
    var multiplier: u64 = options.default_unit;

    // Check for size suffix
    if (options.allow_suffixes and input.len > 0) {
        const last = input[input.len - 1];
        switch (last) {
            'k', 'K' => {
                multiplier = 1024;
                end -= 1;
            },
            'm', 'M' => {
                multiplier = 1024 * 1024;
                end -= 1;
            },
            'g', 'G' => {
                multiplier = 1024 * 1024 * 1024;
                end -= 1;
            },
            't', 'T' => {
                multiplier = 1024 * 1024 * 1024 * 1024;
                end -= 1;
            },
            'b', 'B' => {
                // Check for KB, MB, GB, TB
                if (input.len > 1) {
                    const second_last = input[input.len - 2];
                    switch (second_last) {
                        'k', 'K' => {
                            multiplier = 1024;
                            end -= 2;
                        },
                        'm', 'M' => {
                            multiplier = 1024 * 1024;
                            end -= 2;
                        },
                        'g', 'G' => {
                            multiplier = 1024 * 1024 * 1024;
                            end -= 2;
                        },
                        't', 'T' => {
                            multiplier = 1024 * 1024 * 1024 * 1024;
                            end -= 2;
                        },
                        else => {
                            end -= 1; // Just 'B'
                        },
                    }
                } else {
                    end -= 1;
                }
            },
            '0'...'9' => {}, // No suffix
            else => return SizeParseError.InvalidSuffix,
        }
    }

    if (end == 0) {
        return SizeParseError.EmptyInput;
    }

    // Parse the numeric part
    const num_str = std.mem.trim(u8, input[0..end], " \t");
    if (num_str.len == 0) {
        return SizeParseError.EmptyInput;
    }

    const base_value = std.fmt.parseInt(u64, num_str, 10) catch |err| switch (err) {
        error.Overflow => return SizeParseError.Overflow,
        error.InvalidCharacter => return SizeParseError.InvalidCharacter,
    };

    // Check for overflow during multiplication
    const result = std.math.mul(u64, base_value, multiplier) catch {
        return SizeParseError.Overflow;
    };

    // Bounds check
    if (result < options.min) {
        return SizeParseError.BelowMinimum;
    }
    if (result > options.max) {
        return SizeParseError.AboveMaximum;
    }

    return result;
}

pub const TimestampParseOptions = struct {
    /// Minimum allowed timestamp (default: 0 = Unix epoch)
    min: i64 = 0,
    /// Maximum allowed timestamp (default: year 2100)
    max: i64 = 4102444800,
    /// Allow negative timestamps (before Unix epoch)
    allow_negative: bool = false,
};

pub const TimestampParseError = error{
    EmptyInput,
    InvalidCharacter,
    Overflow,
    BelowMinimum,
    AboveMaximum,
    NegativeNotAllowed,
};

/// Parse a Unix timestamp with bounds checking
pub fn parseTimestamp(input: []const u8, options: TimestampParseOptions) TimestampParseError!i64 {
    if (input.len == 0) {
        return TimestampParseError.EmptyInput;
    }

    const trimmed = std.mem.trim(u8, input, " \t");
    if (trimmed.len == 0) {
        return TimestampParseError.EmptyInput;
    }

    // Check for negative
    const is_negative = trimmed[0] == '-';
    if (is_negative and !options.allow_negative) {
        return TimestampParseError.NegativeNotAllowed;
    }

    const result = std.fmt.parseInt(i64, trimmed, 10) catch |err| switch (err) {
        error.Overflow => return TimestampParseError.Overflow,
        error.InvalidCharacter => return TimestampParseError.InvalidCharacter,
    };

    if (result < options.min) {
        return TimestampParseError.BelowMinimum;
    }
    if (result > options.max) {
        return TimestampParseError.AboveMaximum;
    }

    return result;
}

pub const IntParseOptions = struct {
    min: i64 = std.math.minInt(i64),
    max: i64 = std.math.maxInt(i64),
};

pub const IntParseError = error{
    EmptyInput,
    InvalidCharacter,
    Overflow,
    BelowMinimum,
    AboveMaximum,
};

/// Parse an integer with bounds checking
pub fn parseInt(input: []const u8, options: IntParseOptions) IntParseError!i64 {
    if (input.len == 0) {
        return IntParseError.EmptyInput;
    }

    const trimmed = std.mem.trim(u8, input, " \t");
    if (trimmed.len == 0) {
        return IntParseError.EmptyInput;
    }

    const result = std.fmt.parseInt(i64, trimmed, 10) catch |err| switch (err) {
        error.Overflow => return IntParseError.Overflow,
        error.InvalidCharacter => return IntParseError.InvalidCharacter,
    };

    if (result < options.min) {
        return IntParseError.BelowMinimum;
    }
    if (result > options.max) {
        return IntParseError.AboveMaximum;
    }

    return result;
}

// ============================================================================
// Path Validation
// ============================================================================

pub const PathValidationOptions = struct {
    /// Allow absolute paths
    allow_absolute: bool = true,
    /// Allow relative paths
    allow_relative: bool = true,
    /// Maximum path length
    max_length: usize = 4096,
    /// Allow path traversal (..)
    allow_traversal: bool = false,
    /// Allow hidden files/directories (starting with .)
    allow_hidden: bool = true,
};

pub const PathValidationError = error{
    EmptyPath,
    PathTooLong,
    NullByte,
    ControlCharacter,
    TraversalNotAllowed,
    AbsoluteNotAllowed,
    RelativeNotAllowed,
    HiddenNotAllowed,
    InvalidCharacter,
};

/// Validate a filesystem path
pub fn validatePath(path: []const u8, options: PathValidationOptions) PathValidationError!void {
    if (path.len == 0) {
        return PathValidationError.EmptyPath;
    }

    if (path.len > options.max_length) {
        return PathValidationError.PathTooLong;
    }

    // Check for null bytes
    if (std.mem.indexOfScalar(u8, path, 0) != null) {
        return PathValidationError.NullByte;
    }

    // Check for control characters
    for (path) |c| {
        if (c < 0x20 and c != '\t') {
            return PathValidationError.ControlCharacter;
        }
    }

    // Check absolute vs relative
    const is_absolute = path[0] == '/';
    if (is_absolute and !options.allow_absolute) {
        return PathValidationError.AbsoluteNotAllowed;
    }
    if (!is_absolute and !options.allow_relative) {
        return PathValidationError.RelativeNotAllowed;
    }

    // Check for path traversal
    if (!options.allow_traversal) {
        // Check for .. as a component
        var iter = std.mem.splitScalar(u8, path, '/');
        while (iter.next()) |component| {
            if (std.mem.eql(u8, component, "..")) {
                return PathValidationError.TraversalNotAllowed;
            }
        }
    }

    // Check for hidden files
    if (!options.allow_hidden) {
        var iter = std.mem.splitScalar(u8, path, '/');
        while (iter.next()) |component| {
            if (component.len > 0 and component[0] == '.' and !std.mem.eql(u8, component, ".")) {
                return PathValidationError.HiddenNotAllowed;
            }
        }
    }
}

// ============================================================================
// YAML String Validation
// ============================================================================

/// Check if a YAML string value needs quoting
pub fn yamlNeedsQuoting(value: []const u8) bool {
    if (value.len == 0) return true;

    // Check for special YAML values
    const special_values = [_][]const u8{
        "true", "false", "yes", "no", "on", "off",
        "null", "~", "True", "False", "Yes", "No",
        "TRUE", "FALSE", "YES", "NO", "NULL",
    };

    for (special_values) |special| {
        if (std.mem.eql(u8, value, special)) return true;
    }

    // Check if it looks like a number
    if (std.fmt.parseFloat(f64, value)) |_| {
        return true;
    } else |_| {}

    // Check for special characters that need quoting
    for (value) |c| {
        switch (c) {
            ':', '#', '[', ']', '{', '}', ',', '&', '*', '!', '|', '>', '\'', '"', '%', '@', '`' => return true,
            '\n', '\r', '\t' => return true,
            else => {},
        }
    }

    // Check if starts with special characters
    if (value[0] == '-' or value[0] == '?' or value[0] == ' ') return true;

    return false;
}

/// Escape a string for YAML (double-quoted style)
pub fn escapeYamlString(_: Allocator, input: []const u8) ![]const u8 {
    var result = std.ArrayList(u8).empty;
    errdefer result.deinit();

    for (input) |c| {
        switch (c) {
            '"' => try result.appendSlice("\\\""),
            '\\' => try result.appendSlice("\\\\"),
            '\n' => try result.appendSlice("\\n"),
            '\r' => try result.appendSlice("\\r"),
            '\t' => try result.appendSlice("\\t"),
            else => {
                if (c < 0x20) {
                    try result.writer().print("\\x{x:0>2}", .{c});
                } else {
                    try result.append(c);
                }
            },
        }
    }

    return result.toOwnedSlice();
}

// ============================================================================
// Tests
// ============================================================================

test "URL validation - valid URLs" {
    const valid_urls = [_][]const u8{
        "http://example.com",
        "https://example.com/path",
        "http://example.com:8080",
        "https://example.com:443/path?query=1",
        "http://localhost",
        "http://127.0.0.1",
        "http://[::1]",
        "http://[::1]:8080/path",
        "file:///path/to/file",
    };

    for (valid_urls) |url| {
        const result = UrlValidator.validate(url);
        try std.testing.expect(result.valid);
    }
}

test "URL validation - invalid URLs" {
    const result1 = UrlValidator.validate("");
    try std.testing.expect(!result1.valid);

    const result2 = UrlValidator.validate("not-a-url");
    try std.testing.expect(!result2.valid);

    const result3 = UrlValidator.validate("http://");
    try std.testing.expect(!result3.valid);

    const result4 = UrlValidator.validate("http://example.com/../../../etc/passwd");
    try std.testing.expect(!result4.valid);

    // Null byte injection
    const result5 = UrlValidator.validate("http://example.com\x00evil");
    try std.testing.expect(!result5.valid);
}

test "JSON escaping" {
    const allocator = std.testing.allocator;

    const input = "Hello \"World\"\nNew\\Line";
    const escaped = try escapeJsonString(allocator, input);
    defer allocator.free(escaped);

    try std.testing.expectEqualStrings("Hello \\\"World\\\"\\nNew\\\\Line", escaped);
}

test "JSON escaping - control characters" {
    const allocator = std.testing.allocator;

    const input = "Tab:\tNull:\x00End";
    const escaped = try escapeJsonString(allocator, input);
    defer allocator.free(escaped);

    try std.testing.expect(std.mem.indexOf(u8, escaped, "\\t") != null);
    try std.testing.expect(std.mem.indexOf(u8, escaped, "\\u0000") != null);
}

test "parseSize - basic values" {
    try std.testing.expectEqual(@as(u64, 100), try parseSize("100", .{}));
    try std.testing.expectEqual(@as(u64, 1024), try parseSize("1K", .{}));
    try std.testing.expectEqual(@as(u64, 1024), try parseSize("1k", .{}));
    try std.testing.expectEqual(@as(u64, 1048576), try parseSize("1M", .{}));
    try std.testing.expectEqual(@as(u64, 1073741824), try parseSize("1G", .{}));
    try std.testing.expectEqual(@as(u64, 1024), try parseSize("1KB", .{}));
}

test "parseSize - bounds checking" {
    const result1 = parseSize("100", .{ .min = 200 });
    try std.testing.expectError(SizeParseError.BelowMinimum, result1);

    const result2 = parseSize("100", .{ .max = 50 });
    try std.testing.expectError(SizeParseError.AboveMaximum, result2);
}

test "parseTimestamp - valid values" {
    try std.testing.expectEqual(@as(i64, 0), try parseTimestamp("0", .{}));
    try std.testing.expectEqual(@as(i64, 1702400000), try parseTimestamp("1702400000", .{}));
}

test "parseTimestamp - bounds checking" {
    // Future date beyond year 2100
    const result = parseTimestamp("9999999999999", .{});
    try std.testing.expectError(TimestampParseError.AboveMaximum, result);
}

test "path validation" {
    try validatePath("/usr/local/bin", .{});
    try validatePath("relative/path", .{});

    // Path traversal
    const result1 = validatePath("../../../etc/passwd", .{ .allow_traversal = false });
    try std.testing.expectError(PathValidationError.TraversalNotAllowed, result1);

    // Absolute not allowed
    const result2 = validatePath("/absolute/path", .{ .allow_absolute = false });
    try std.testing.expectError(PathValidationError.AbsoluteNotAllowed, result2);

    // Null byte
    const result3 = validatePath("path\x00evil", .{});
    try std.testing.expectError(PathValidationError.NullByte, result3);
}

test "YAML needs quoting" {
    try std.testing.expect(yamlNeedsQuoting("true"));
    try std.testing.expect(yamlNeedsQuoting("false"));
    try std.testing.expect(yamlNeedsQuoting("123"));
    try std.testing.expect(yamlNeedsQuoting("value: with colon"));
    try std.testing.expect(yamlNeedsQuoting("# comment"));
    try std.testing.expect(!yamlNeedsQuoting("simple_value"));
    try std.testing.expect(!yamlNeedsQuoting("another-value"));
}
