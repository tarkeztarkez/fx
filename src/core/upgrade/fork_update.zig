const std = @import("std");
const io_mod = @import("../shared/io.zig");
const upgrade_helpers = @import("upgrade_helpers.zig");

const Allocator = std.mem.Allocator;

pub const RunResult = struct {
    output: []u8,
    succeeded: bool,

    pub fn deinit(self: *RunResult, alloc: Allocator) void {
        alloc.free(self.output);
        self.* = undefined;
    }
};

fn repoPath(alloc: Allocator) ![]u8 {
    if (io_mod.getenv("FX_FORK_REPO")) |path| return alloc.dupe(u8, path);
    const home = io_mod.getenv("HOME") orelse return error.HomeNotSet;
    return repoPathForHome(alloc, home);
}

fn repoPathForHome(alloc: Allocator, home: []const u8) ![]u8 {
    return std.fs.path.join(alloc, &.{ home, "Projects", "fx" });
}

pub fn updateAvailable(alloc: Allocator) bool {
    const repo = repoPath(alloc) catch return false;
    defer alloc.free(repo);

    const fetch = std.process.run(alloc, io_mod.getIo(), .{
        .argv = &.{ "git", "-C", repo, "fetch", "--quiet", "upstream", "main" },
    }) catch return false;
    defer alloc.free(fetch.stdout);
    defer alloc.free(fetch.stderr);
    if (fetch.term != .exited or fetch.term.exited != 0) return false;

    const check = std.process.run(alloc, io_mod.getIo(), .{
        .argv = &.{ "git", "-C", repo, "merge-base", "--is-ancestor", "upstream/main", "HEAD" },
    }) catch return false;
    defer alloc.free(check.stdout);
    defer alloc.free(check.stderr);
    return check.term == .exited and check.term.exited == 1;
}

pub fn run(alloc: Allocator) !RunResult {
    const repo = try repoPath(alloc);
    defer alloc.free(repo);
    const script = try std.fs.path.join(alloc, &.{ repo, "scripts", "fork-update.sh" });
    defer alloc.free(script);

    var executable_buf: [std.fs.max_path_bytes]u8 = undefined;
    const executable = try upgrade_helpers.currentExecutablePath(&executable_buf);
    const result = try std.process.run(alloc, io_mod.getIo(), .{
        .argv = &.{ "/bin/sh", script, executable },
    });
    defer alloc.free(result.stdout);
    defer alloc.free(result.stderr);

    var out: std.Io.Writer.Allocating = .init(alloc);
    defer out.deinit();
    try out.writer.writeAll(result.stdout);
    if (result.stderr.len > 0) {
        if (result.stdout.len > 0 and result.stdout[result.stdout.len - 1] != '\n') try out.writer.writeByte('\n');
        try out.writer.writeAll(result.stderr);
    }
    const succeeded = result.term == .exited and result.term.exited == 0;
    return .{ .output = try out.toOwnedSlice(), .succeeded = succeeded };
}

test "fork repository defaults under home" {
    const path = try repoPathForHome(std.testing.allocator, "/tmp/home");
    defer std.testing.allocator.free(path);
    try std.testing.expectEqualStrings("/tmp/home/Projects/fx", path);
}
