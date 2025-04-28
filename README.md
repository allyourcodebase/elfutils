[![CI](https://github.com/allyourcodebase/elfutils/actions/workflows/ci.yaml/badge.svg)](https://github.com/allyourcodebase/elfutils/actions)

# elfutils

This is [elfutils](https://sourceware.org/elfutils/), packaged for [Zig](https://ziglang.org/).

## Installation

First, update your `build.zig.zon`:

```
# Initialize a `zig build` project if you haven't already
zig init
zig fetch --save git+https://github.com/allyourcodebase/elfutils.git
```

You can then import `elfutils` in your `build.zig` with:

```zig
const elfutils_dependency = b.dependency("elfutils", .{
    .target = target,
    .optimize = optimize,
});
const libelf = elfutils_dependency.artifact("elf");
const libdw = elfutils_dependency.artifact("dw");
const libasm = elfutils_dependency.artifact("asm");

your_exe.linkLibrary(libelf);
your_exe.linkLibrary(libdw);
your_exe.linkLibrary(libasm);
```
