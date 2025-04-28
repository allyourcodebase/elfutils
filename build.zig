const std = @import("std");

const version: std.SemanticVersion = .{ .major = 0, .minor = 192, .patch = 0 };

pub fn build(b: *std.Build) void {
    const upstream = b.dependency("elfutils", .{});
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const linkage = b.option(std.builtin.LinkMode, "linkage", "Link mode") orelse .static;
    const strip = b.option(bool, "strip", "Omit debug information");
    const pic = b.option(bool, "pie", "Produce Position Independent Code");

    const use_zlib = b.option(bool, "zlib", "Use zlib") orelse true;
    const use_zstd = b.option(bool, "zstd", "Use zstd") orelse true;

    const config_header = b.addConfigHeader(.{ .style = .{ .autoconf = b.path("config.h.in") } }, .{
        .CHECK_UNDEFINED = switch (optimize) {
            .Debug, .ReleaseSafe => true,
            .ReleaseFast, .ReleaseSmall => false,
        },
        .DEFAULT_AR_DETERMINISTIC = false,
        .DUMMY_LIBDEBUGINFOD = null,
        .ENABLE_DEBUGINFOD = null,
        .ENABLE_IMA_VERIFICATION = null,
        .ENABLE_LIBDEBUGINFOD = null,
        .ENABLE_NLS = true,
        .HAVE_CFLOCALECOPYPREFERREDLANGUAGES = null,
        .HAVE_CFPREFERENCESCOPYAPPVALUE = null,
        .HAVE_CXX11 = true,
        .HAVE_DCGETTEXT = true,
        .HAVE_DECL_MEMPCPY = true,
        .HAVE_DECL_MEMRCHR = true,
        .HAVE_DECL_POWEROF2 = true,
        .HAVE_DECL_RAWMEMCHR = false,
        .HAVE_DECL_REALLOCARRAY = true,
        .HAVE_DECL_STRERROR_R = true,
        .HAVE_ERROR_H = null,
        .HAVE_ERR_H = true,
        .HAVE_EXECINFO_H = null,
        .HAVE_FALLTHROUGH = true,
        .HAVE_GCC_STRUCT = null,
        .HAVE_GETRLIMIT = true,
        .HAVE_GETTEXT = true,
        .HAVE_ICONV = null,
        .HAVE_INTTYPES_H = true,
        .HAVE_LIBARCHIVE = null,
        .HAVE_MALLOC_H = true,
        .HAVE_MALLOC_TRIM = null,
        .HAVE_MREMAP = true,
        .HAVE_PROCESS_VM_READV = true,
        .HAVE_PTHREAD_SETNAME_NP = true,
        .HAVE_SCHED_GETAFFINITY = true,
        .HAVE_SCHED_H = true,
        .HAVE_STDATOMIC_H = true,
        .HAVE_STDINT_H = true,
        .HAVE_STDIO_H = true,
        .HAVE_STDLIB_H = true,
        .HAVE_STRERROR_R = true,
        .HAVE_STRINGS_H = true,
        .HAVE_STRING_H = true,
        .HAVE_SYSPROF_4_HEADERS = null,
        .HAVE_SYSPROF_6_HEADERS = null,
        .HAVE_SYS_RESOURCE_H = true,
        .HAVE_SYS_STAT_H = true,
        .HAVE_SYS_TYPES_H = true,
        .HAVE_SYS_USER_REGS = true,
        .HAVE_UNISTD_H = true,
        .HAVE_VISIBILITY = true,
        .PACKAGE = "elfutils",
        .PACKAGE_BUGREPORT = "https://sourceware.org/bugzilla",
        .PACKAGE_NAME = "elfutils",
        .PACKAGE_STRING = b.fmt("elfutils {}.{}", .{ version.major, version.minor }),
        .PACKAGE_TARNAME = "elfutils",
        .PACKAGE_URL = "http://elfutils.org/",
        .PACKAGE_VERSION = b.fmt("{}.{}", .{ version.major, version.minor }),
        .SIZEOF_LONG = target.result.cTypeByteSize(.long),
        .STDC_HEADERS = true,
        .STRERROR_R_CHAR_P = null,
        .USE_BZLIB = null, // TODO
        .USE_DEMANGLE = true,
        .USE_LOCKS = null,
        .USE_LZMA = null, // TODO
        .USE_ZLIB = use_zlib,
        .USE_ZSTD = use_zstd,
        .USE_ZSTD_COMPRESS = use_zstd,
        .VERSION = b.fmt("{}.{}", .{ version.major, version.minor }),
        .YYTEXT_POINTER = null,
        ._FILE_OFFSET_BITS = null,
        ._LARGE_FILES = null,
    });

    const libeu = b.addLibrary(.{
        .linkage = linkage,
        .name = "eu",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .strip = strip,
            .pic = pic,
            .link_libc = true,
        }),
    });
    libeu.root_module.addConfigHeader(config_header);
    libeu.root_module.addCMacro("HAVE_CONFIG_H", "1");
    libeu.root_module.addCMacro("_GNU_SOURCE", "1");
    libeu.root_module.addIncludePath(upstream.path("lib"));
    libeu.root_module.addCSourceFiles(.{
        .root = upstream.path("lib"),
        .files = libeu_sources,
    });

    if (!target.result.isGnuLibC()) {
        if (b.systemIntegrationOption("argp", .{})) {
            libeu.root_module.linkSystemLibrary("argp", .{});
        } else if (b.lazyDependency("argp_standalone", .{
            .target = target,
            .optimize = optimize,
        })) |dependency| {
            libeu.root_module.linkLibrary(dependency.artifact("argp"));
        }
    }

    const libelf = b.addLibrary(.{
        .linkage = linkage,
        .name = "elf",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .strip = strip,
            .pic = pic,
            .link_libc = true,
        }),
    });
    b.installArtifact(libelf);
    libelf.installHeader(upstream.path("libelf/libelf.h"), "libelf.h");
    libelf.installHeader(upstream.path("libelf/gelf.h"), "gelf.h");
    libelf.installHeader(upstream.path("libelf/nlist.h"), "nlist.h");
    libelf.root_module.linkLibrary(libeu);
    libelf.root_module.addConfigHeader(config_header);
    libelf.root_module.addCMacro("HAVE_CONFIG_H", "1");
    libelf.root_module.addCMacro("_GNU_SOURCE", "1");
    libelf.root_module.addIncludePath(upstream.path("lib"));
    libelf.root_module.addIncludePath(upstream.path("libelf"));
    libelf.root_module.addCSourceFiles(.{
        .root = upstream.path("libelf"),
        .files = libelf_sources,
    });

    if (use_zlib) {
        if (b.systemIntegrationOption("zlib", .{})) {
            libelf.root_module.linkSystemLibrary("z", .{});
        } else {
            if (b.lazyDependency("zlib", .{
                .target = target,
                .optimize = optimize,
            })) |dependency| {
                libelf.root_module.linkLibrary(dependency.artifact("z"));
            }
        }
    }

    if (use_zstd) {
        if (b.systemIntegrationOption("zstd", .{})) {
            libelf.root_module.linkSystemLibrary("zstd", .{});
        } else {
            if (b.lazyDependency("zstd", .{
                .target = target,
                .optimize = optimize,
            })) |dependency| {
                libelf.root_module.linkLibrary(dependency.artifact("zstd"));
            }
        }
    }

    const libdwelf = b.addLibrary(.{
        .linkage = linkage,
        .name = "dwelf",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .strip = strip,
            .pic = pic,
            .link_libc = true,
        }),
    });
    b.installArtifact(libdwelf);
    libdwelf.installHeader(upstream.path("libdwelf/libdwelf.h"), "libdwelf.h");
    libdwelf.root_module.addConfigHeader(config_header);
    libdwelf.root_module.addCMacro("HAVE_CONFIG_H", "1");
    libdwelf.root_module.addCMacro("_GNU_SOURCE", "1");
    libdwelf.root_module.addIncludePath(upstream.path("libdwelf"));
    libdwelf.root_module.addIncludePath(upstream.path("libelf"));
    libdwelf.root_module.addIncludePath(upstream.path("libdw"));
    libdwelf.root_module.addIncludePath(upstream.path("libdwfl"));
    libdwelf.root_module.addIncludePath(upstream.path("libebl"));
    libdwelf.root_module.addIncludePath(upstream.path("lib"));
    libdwelf.root_module.addCSourceFiles(.{
        .root = upstream.path("libdwelf"),
        .files = libdwelf_sources,
    });

    const libebl = b.addLibrary(.{
        .linkage = linkage,
        .name = "ebl",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .strip = strip,
            .pic = pic,
            .link_libc = true,
        }),
    });
    libebl.installHeader(upstream.path("libebl/libebl.h"), "libebl.h");
    libebl.root_module.addConfigHeader(config_header);
    libebl.root_module.addCMacro("HAVE_CONFIG_H", "1");
    libebl.root_module.addCMacro("_GNU_SOURCE", "1");
    libebl.root_module.addIncludePath(upstream.path("libebl"));
    libebl.root_module.addIncludePath(upstream.path("libelf"));
    libebl.root_module.addIncludePath(upstream.path("libdw"));
    libebl.root_module.addIncludePath(upstream.path("libasm"));
    libebl.root_module.addIncludePath(upstream.path("lib"));
    libebl.root_module.addCSourceFiles(.{
        .root = upstream.path("libebl"),
        .files = libebl_sources,
    });

    const libdw = b.addLibrary(.{
        .linkage = linkage,
        .name = "dw",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .strip = strip,
            .pic = pic,
            .link_libc = true,
        }),
    });
    b.installArtifact(libdw);
    libdw.installHeader(upstream.path("libdw/libdw.h"), "elfutils/libdw.h");
    libdw.installHeader(b.path("known-dwarf.h"), "elfutils/known-dwarf.h");
    libdw.installHeader(upstream.path("libdw/dwarf.h"), "dwarf.h");
    libdw.root_module.linkLibrary(libeu);
    libdw.root_module.linkLibrary(libelf);
    libdw.root_module.linkLibrary(libdwelf);
    libdw.root_module.linkLibrary(libebl);
    libdw.root_module.addConfigHeader(config_header);
    libdw.root_module.addCMacro("HAVE_CONFIG_H", "1");
    libdw.root_module.addCMacro("_GNU_SOURCE", "1");
    libdw.root_module.addIncludePath(upstream.path("libdw"));
    libdw.root_module.addIncludePath(upstream.path("libelf"));
    libdw.root_module.addIncludePath(upstream.path("libebl"));
    libdw.root_module.addIncludePath(upstream.path("libdwelf"));
    libdw.root_module.addIncludePath(upstream.path("lib"));
    libdw.root_module.addCSourceFiles(.{
        .root = upstream.path("libdw"),
        .files = libdw_sources,
    });
}

const libeu_sources: []const []const u8 = &.{
    "xasprintf.c",
    "xstrdup.c",
    "xstrndup.c",
    "xmalloc.c",
    "next_prime.c",
    "crc32.c",
    "crc32_file.c",
    "eu-search.c",
    "color.c",
    "error.c",
    "printversion.c",
};

const libelf_sources: []const []const u8 = &.{
    "elf_version.c",
    "elf_hash.c",
    "elf_error.c",
    "elf_fill.c",
    "elf_begin.c",
    "elf_next.c",
    "elf_rand.c",
    "elf_end.c",
    "elf_kind.c",
    "gelf_getclass.c",
    "elf_getbase.c",
    "elf_getident.c",
    "elf32_fsize.c",
    "elf64_fsize.c",
    "gelf_fsize.c",
    "elf32_xlatetof.c",
    "elf32_xlatetom.c",
    "elf64_xlatetof.c",
    "elf64_xlatetom.c",
    "gelf_xlate.c",
    "elf32_getehdr.c",
    "elf64_getehdr.c",
    "gelf_getehdr.c",
    "elf32_newehdr.c",
    "elf64_newehdr.c",
    "gelf_newehdr.c",
    "gelf_update_ehdr.c",
    "elf32_getphdr.c",
    "elf64_getphdr.c",
    "gelf_getphdr.c",
    "elf32_newphdr.c",
    "elf64_newphdr.c",
    "gelf_newphdr.c",
    "gelf_update_phdr.c",
    "elf_getarhdr.c",
    "elf_getarsym.c",
    "elf_rawfile.c",
    "elf_readall.c",
    "elf_cntl.c",
    "elf_getscn.c",
    "elf_nextscn.c",
    "elf_ndxscn.c",
    "elf_newscn.c",
    "elf32_getshdr.c",
    "elf64_getshdr.c",
    "gelf_getshdr.c",
    "gelf_update_shdr.c",
    "elf_strptr.c",
    "elf_rawdata.c",
    "elf_getdata.c",
    "elf_newdata.c",
    "elf_getdata_rawchunk.c",
    "elf_flagelf.c",
    "elf_flagehdr.c",
    "elf_flagphdr.c",
    "elf_flagscn.c",
    "elf_flagshdr.c",
    "elf_flagdata.c",
    "elf_memory.c",
    "elf_update.c",
    "elf32_updatenull.c",
    "elf64_updatenull.c",
    "elf32_updatefile.c",
    "elf64_updatefile.c",
    "gelf_getsym.c",
    "gelf_update_sym.c",
    "gelf_getversym.c",
    "gelf_getverneed.c",
    "gelf_getvernaux.c",
    "gelf_getverdef.c",
    "gelf_getverdaux.c",
    "gelf_getrel.c",
    "gelf_getrela.c",
    "gelf_update_rel.c",
    "gelf_update_rela.c",
    "gelf_getdyn.c",
    "gelf_update_dyn.c",
    "gelf_getmove.c",
    "gelf_update_move.c",
    "gelf_getsyminfo.c",
    "gelf_update_syminfo.c",
    "gelf_getauxv.c",
    "gelf_update_auxv.c",
    "gelf_getnote.c",
    "gelf_xlatetof.c",
    "gelf_xlatetom.c",
    "nlist.c",
    "gelf_getsymshndx.c",
    "gelf_update_symshndx.c",
    "gelf_update_versym.c",
    "gelf_update_verneed.c",
    "gelf_update_vernaux.c",
    "gelf_update_verdef.c",
    "gelf_update_verdaux.c",
    "elf_getphdrnum.c",
    "elf_getshdrnum.c",
    "elf_getshdrstrndx.c",
    "gelf_checksum.c",
    "elf32_checksum.c",
    "elf64_checksum.c",
    "libelf_crc32.c",
    "libelf_next_prime.c",
    "elf_clone.c",
    "gelf_getlib.c",
    "gelf_update_lib.c",
    "elf32_offscn.c",
    "elf64_offscn.c",
    "gelf_offscn.c",
    "elf_getaroff.c",
    "elf_gnu_hash.c",
    "elf_scnshndx.c",
    "elf32_getchdr.c",
    "elf64_getchdr.c",
    "gelf_getchdr.c",
    "elf_compress.c",
    "elf_compress_gnu.c",
};

const libdwelf_sources: []const []const u8 = &.{
    "dwelf_elf_gnu_debuglink.c",
    "dwelf_dwarf_gnu_debugaltlink.c",
    "dwelf_elf_gnu_build_id.c",
    "dwelf_scn_gnu_compressed_size.c",
    "dwelf_strtab.c",
    "dwelf_elf_begin.c",
    "dwelf_elf_e_machine_string.c",
};

const libebl_sources: []const []const u8 = &.{
    "eblopenbackend.c",
    "eblclosebackend.c",
    "eblreloctypename.c",
    "eblsegmenttypename.c",
    "eblsectiontypename.c",
    "eblmachineflagname.c",
    "eblsymboltypename.c",
    "ebldynamictagname.c",
    "eblsectionname.c",
    "eblsymbolbindingname.c",
    "eblbackendname.c",
    "eblosabiname.c",
    "eblmachineflagcheck.c",
    "eblmachinesectionflagcheck.c",
    "eblreloctypecheck.c",
    "eblrelocvaliduse.c",
    "eblrelocsimpletype.c",
    "ebldynamictagcheck.c",
    "eblcorenotetypename.c",
    "eblobjnotetypename.c",
    "eblcorenote.c",
    "eblobjnote.c",
    "ebldebugscnp.c",
    "eblgotpcreloccheck.c",
    "eblcopyrelocp.c",
    "eblsectionstripp.c",
    "eblelfclass.c",
    "eblelfdata.c",
    "eblelfmachine.c",
    "ebl_check_special_symbol.c",
    "eblbsspltp.c",
    "eblretval.c",
    "eblreginfo.c",
    "eblnonerelocp.c",
    "eblrelativerelocp.c",
    "eblsysvhashentrysize.c",
    "eblauxvinfo.c",
    "eblcheckobjattr.c",
    "ebl_check_special_section.c",
    "eblabicfi.c",
    "eblstother.c",
    "eblinitreg.c",
    "ebldwarftoregno.c",
    "eblnormalizepc.c",
    "eblunwind.c",
    "eblresolvesym.c",
    "eblcheckreloctargettype.c",
    "ebl_data_marker_symbol.c",
};

const libdw_sources: []const []const u8 = &.{
    "dwarf_begin.c",
    "dwarf_begin_elf.c",
    "dwarf_end.c",
    "dwarf_getelf.c",
    "dwarf_getpubnames.c",
    "dwarf_getabbrev.c",
    "dwarf_tag.c",
    "dwarf_error.c",
    "dwarf_nextcu.c",
    "dwarf_diename.c",
    "dwarf_offdie.c",
    "dwarf_attr.c",
    "dwarf_formstring.c",
    "dwarf_abbrev_hash.c",
    "dwarf_sig8_hash.c",
    "dwarf_attr_integrate.c",
    "dwarf_hasattr_integrate.c",
    "dwarf_child.c",
    "dwarf_haschildren.c",
    "dwarf_formaddr.c",
    "dwarf_formudata.c",
    "dwarf_formsdata.c",
    "dwarf_lowpc.c",
    "dwarf_entrypc.c",
    "dwarf_haspc.c",
    "dwarf_highpc.c",
    "dwarf_ranges.c",
    "dwarf_formref.c",
    "dwarf_formref_die.c",
    "dwarf_siblingof.c",
    "dwarf_dieoffset.c",
    "dwarf_cuoffset.c",
    "dwarf_diecu.c",
    "dwarf_hasattr.c",
    "dwarf_hasform.c",
    "dwarf_whatform.c",
    "dwarf_whatattr.c",
    "dwarf_bytesize.c",
    "dwarf_arrayorder.c",
    "dwarf_bitsize.c",
    "dwarf_bitoffset.c",
    "dwarf_srclang.c",
    "dwarf_getabbrevtag.c",
    "dwarf_getabbrevcode.c",
    "dwarf_abbrevhaschildren.c",
    "dwarf_getattrcnt.c",
    "dwarf_getabbrevattr.c",
    "dwarf_getsrclines.c",
    "dwarf_getsrc_die.c",
    "dwarf_getscopes.c",
    "dwarf_getscopes_die.c",
    "dwarf_getscopevar.c",
    "dwarf_linesrc.c",
    "dwarf_lineno.c",
    "dwarf_lineaddr.c",
    "dwarf_linecol.c",
    "dwarf_linebeginstatement.c",
    "dwarf_lineendsequence.c",
    "dwarf_lineblock.c",
    "dwarf_linecontext.c",
    "dwarf_linefunctionname.c",
    "dwarf_lineprologueend.c",
    "dwarf_lineepiloguebegin.c",
    "dwarf_lineisa.c",
    "dwarf_linediscriminator.c",
    "dwarf_lineop_index.c",
    "dwarf_line_file.c",
    "dwarf_onesrcline.c",
    "dwarf_formblock.c",
    "dwarf_getsrcfiles.c",
    "dwarf_filesrc.c",
    "dwarf_getsrcdirs.c",
    "dwarf_getlocation.c",
    "dwarf_getstring.c",
    "dwarf_offabbrev.c",
    "dwarf_getaranges.c",
    "dwarf_onearange.c",
    "dwarf_getarangeinfo.c",
    "dwarf_getarange_addr.c",
    "dwarf_getattrs.c",
    "dwarf_formflag.c",
    "dwarf_getmacros.c",
    "dwarf_macro_getparamcnt.c",
    "dwarf_macro_opcode.c",
    "dwarf_macro_param.c",
    "dwarf_macro_param1.c",
    "dwarf_macro_param2.c",
    "dwarf_macro_getsrcfiles.c",
    "dwarf_addrdie.c",
    "dwarf_getfuncs.c",
    "dwarf_decl_file.c",
    "dwarf_decl_line.c",
    "dwarf_decl_column.c",
    "dwarf_func_inline.c",
    "dwarf_getsrc_file.c",
    "libdw_findcu.c",
    "libdw_form.c",
    "libdw_alloc.c",
    "libdw_visit_scopes.c",
    "dwarf_entry_breakpoints.c",
    "dwarf_next_cfi.c",
    "cie.c",
    "fde.c",
    "cfi.c",
    "frame-cache.c",
    "dwarf_frame_info.c",
    "dwarf_frame_cfa.c",
    "dwarf_frame_register.c",
    "dwarf_cfi_addrframe.c",
    "dwarf_getcfi.c",
    "dwarf_getcfi_elf.c",
    "dwarf_cfi_end.c",
    "dwarf_aggregate_size.c",
    "dwarf_getlocation_implicit_pointer.c",
    "dwarf_getlocation_die.c",
    "dwarf_getlocation_attr.c",
    "dwarf_getalt.c",
    "dwarf_setalt.c",
    "dwarf_cu_getdwarf.c",
    "dwarf_cu_die.c",
    "dwarf_peel_type.c",
    "dwarf_default_lower_bound.c",
    "dwarf_die_addr_die.c",
    "dwarf_get_units.c",
    "libdw_find_split_unit.c",
    "dwarf_cu_info.c",
    "dwarf_next_lines.c",
    "dwarf_cu_dwp_section_info.c",
};
