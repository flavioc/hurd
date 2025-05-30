dnl Process this file with autoconf to produce a configure script.
AC_PREREQ([2.69])			dnl Minimum Autoconf version required.
AC_INIT([GNU Hurd], [0.9], [bug-hurd@gnu.org])
AC_CONFIG_SRCDIR([hurd/hurd_types.h])	dnl File to look for in srcdir.

AC_PREFIX_DEFAULT()		dnl Default to empty prefix, not /usr/local.

AC_CANONICAL_HOST
case "$host_os" in
gnu*) ;;
none) AC_MSG_ERROR([
*** You must specify a host of $host_cpu-gnu or $host_cpu-$host_vendor-gnu
*** to configure; you will need to use the same host specification
*** to configure other packages for the GNU/Hurd system.]) ;;
*) AC_MSG_ERROR([this is the gnu os, host cannot be $host_os
*** Host configuration must be `MACHINE-gnu' or `MACHINE-VENDOR-gnu'.
*** To cross-compile, you must specify both --host and --build;
*** for example `--build=$host --host=$host_cpu-gnu'.
*** Run $0 --help for more information.]) ;;
esac

case "$host_cpu" in
alpha*)
  asm_syntax=alpha
  ;;
arm*)
  asm_syntax=arm
  ;;
m68k | m680?0)
  asm_syntax=m68k
  ;;
mips*)
  asm_syntax=mips
  ;;
i?86)
  asm_syntax=i386
  ;;
powerpc*)
  asm_syntax=ppc
  ;;
sparc64* | ultrasparc*)
  asm_syntax=sparc64
  ;;
sparc*)
  asm_syntax=sparc
  ;;
*)
  asm_syntax="$host_cpu"
  ;;
esac
AC_SUBST(asm_syntax)

test -r "$srcdir/pfinet/linux-src/include/asm-$asm_syntax/checksum.h" || {
  AC_MSG_WARN([unsupported CPU type $host_cpu])
}

AC_ARG_ENABLE(profile,
[  --disable-profile	  do not build profiled libraries and programs])
AC_SUBST(enable_profile)

define([default_static],['ext2fs,iso9660fs,rumpdisk,pci-arbiter,acpi'])dnl
AC_ARG_ENABLE(static-progs,
[  --enable-static-progs=PROGRAMS...
                          build statically-linked PROGRAM.static versions
                          of (only) the listed programs ]dnl
changequote(',')[default_static]changequote([,]))
case "$enable_static_progs" in
'no')	enable_static_progs= ;;		# we got --disable-static
'')	enable_static_progs=default_static ;;
esac
# Convert comma/space-separated list into space-separated list.
enable_static_progs=`echo "$enable_static_progs" | sed 's/[[, ]][[, ]]*/ /g'`
AC_SUBST(enable_static_progs)

[# Don't needlessly overwrite files whose contents haven't changed.
# This helps avoiding unnecessary recompilation cycles when keeping
# cross-compilation toolchains up-to-date.  Thus, unconditionally use the
# supplied `install-sh', as the GNU Coreutils one doesn't provide this
# functionality yet (TODO: change that).  TODO: $ac_abs_top_builddir et al. are
# not yet available here, that's why we use `readlink' (but only if available).
INSTALL="$SHELL $(readlink -f "$ac_install_sh")"\ -C || unset INSTALL]
AC_PROG_INSTALL
AC_PROG_AWK
AC_PROG_SED

if test "x$cross_compiling" = "xyes"; then
   # It may be that we don't have a working libc yet, for instance
   # because we're bootstrapping the cross-compilation tool chain.
   # Thus, use this undocumented Autoconf macro designed for this.
   AC_NO_EXECUTABLES
   AC_MSG_WARN("cross-compiling, disabling linking")
fi
AC_PROG_CC
# Require GCC.
if test x$GCC != xyes; then
  AC_MSG_ERROR([this code uses GNU C extensions, you must compile with GCC])
fi

AC_CHECK_TOOL(LD, ld)
AC_CHECK_TOOL(OBJCOPY, objcopy)
AC_CHECK_TOOL(AR, ar)
AC_CHECK_TOOL(RANLIB, ranlib)
AC_CHECK_TOOL(MIG, mig)
# Require MiG.
if test x${MIG} = x; then
  AC_MSG_ERROR([
*** You need GNU MiG to compile the GNU Hurd, please see
*** http://www.gnu.org/software/hurd/microkernel/mach/mig/gnu_mig.html
*** for further details, or download it directly from the main GNU server
*** (ftp.gnu.org) or any GNU mirror.])
fi

dnl Let these propagate from the environment.
AC_SUBST(CFLAGS) AC_SUBST(CPPFLAGS) AC_SUBST(LDFLAGS)

# See if --version-script is available.
AC_CACHE_CHECK(for ld --version-script, hurd_cv_ld_version_script_option, [dnl
cat > conftest.c <<\EOF
void foobar() {}
EOF
cat > conftest.map <<\EOF
VERS_1 {
	global: sym;
};

VERS_2 {
        global: sym;
} VERS_1;
EOF

if AC_TRY_COMMAND([eval $ac_compile 1>&AS_MESSAGE_LOG_FD()]) &&
   AC_TRY_COMMAND([${CC-cc} $CFLAGS -shared -o conftest.so conftest.o
				    -nostartfiles -nostdlib
				    -Wl,--version-script,conftest.map
		   1>&AS_MESSAGE_LOG_FD()]); then
  hurd_cv_ld_version_script_option=yes
else
  hurd_cv_ld_version_script_option=no
fi
rm -f conftest*])

# See if libc was built with --enable-libio.
AC_CACHE_CHECK([for libio],
  hurd_cv_libio,
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <stdio.h>
#ifndef _STDIO_USES_IOSTREAM
# error No libio found.
#endif]],
    [[]])],
    [hurd_cv_libio=yes],
    [hurd_cv_libio=no]))

# Check if libc contains these functions.
AC_CHECK_FUNCS(file_exec_paths exec_exec_paths _hurd_exec_paths)
AC_CHECK_FUNCS(_hurd_libc_proc_init)

# Compatibility with glibc < 2.28
AC_CHECK_FUNCS(file_utimens)
AC_DEFINE([UTIME_NOW],[-1])
AC_DEFINE([UTIME_OMIT],[-2])

AC_ARG_WITH([libcrypt],
  [AS_HELP_STRING([--without-libcrypt], [disable libcrypt])], , [with_libcrypt=yes])

AS_IF([test "x$with_libcrypt" != xno], [
  AC_CHECK_LIB([crypt], [crypt],
	       [HAVE_LIBCRYPT=1
		AC_DEFINE([HAVE_LIBCRYPT], [1], [Use libcrypt])])
])
AC_SUBST([HAVE_LIBCRYPT])

# From glibc HEAD, 2007-11-07.
AC_CACHE_CHECK(for -fgnu89-inline, libc_cv_gnu89_inline, [dnl
cat > conftest.c <<EOF
int foo;
#ifdef __GNUC_GNU_INLINE__
main () { return 0;}
#else
#error
#endif
EOF
if AC_TRY_COMMAND([${CC-cc} $CFLAGS $CPPFLAGS -S -std=gnu99 -fgnu89-inline
			    -o conftest.s conftest.c 1>&AS_MESSAGE_LOG_FD])
then
  libc_cv_gnu89_inline=yes
else
  libc_cv_gnu89_inline=no
fi
rm -f conftest*])
if test $libc_cv_gnu89_inline = yes; then
  libc_cv_gnu89_inline=-fgnu89-inline
else
  libc_cv_gnu89_inline=
fi
AC_SUBST(libc_cv_gnu89_inline)


# Insist on libparted unless the user declines explicitely
AC_ARG_WITH([parted],
  [AS_HELP_STRING([--without-parted], [disable user-space partition stores])],
  [],
  [with_parted=yes])

PARTED_LIBS=
AC_DEFUN([PARTED_FAIL], [
  AC_MSG_FAILURE([Please install required libraries or use --without-parted.])
])
AS_IF([test "x$with_parted" != xno], [
  AC_CHECK_HEADER([parted/parted.h],
    [AC_DEFINE(HAVE_PARTED_PARTED_H)],
    [PARTED_FAIL])
  AC_CHECK_LIB([parted], [ped_device_read], [], [PARTED_FAIL])
  AC_CHECK_LIB([uuid], [uuid_generate], [], [PARTED_FAIL])
  AC_CHECK_LIB([dl], [dlopen], [], [PARTED_FAIL])
  PARTED_LIBS="-lparted -luuid -ldl"
])
AC_SUBST([PARTED_LIBS])

AC_ARG_WITH([libbz2],
  [AS_HELP_STRING([--without-libbz2], [disable libbz2])], , [with_libbz2=yes])

AS_IF([test "x$with_libbz2" != xno], [
  AC_CHECK_LIB(bz2, BZ2_bzCompress, [HAVE_LIBBZ2=1], [true])
])
AC_SUBST([HAVE_LIBBZ2])

AC_ARG_WITH([libz],
  [AS_HELP_STRING([--without-libz], [disable libz])], , [with_libz=yes])

AS_IF([test "x$with_libz" != xno], [
  AC_CHECK_LIB(z, deflate, [HAVE_LIBZ=1], [true])
])
AC_SUBST([HAVE_LIBZ])

AC_ARG_WITH([rump],
  [AS_HELP_STRING([--without-rump], [disable rump])], , [with_rump=yes])

AS_IF([test "x$with_rump" != xno], [
  # Save
  oldLIBS="$LIBS"

  LIBS="$oldLIBS -lrump"
  AC_LINK_IFELSE(
    [AC_LANG_PROGRAM(
      [[#include <hurd.h>
#define _STANDALONE
#include <rump/rump.h>]],
    [])],
    [HAVE_LIBRUMP=yes],
    [HAVE_LIBRUMP=no])
  AC_SUBST([HAVE_LIBRUMP])

  LIBS="$oldLIBS -lrumpvfs_nofifofs_pic"
  AC_LINK_IFELSE(
    [AC_LANG_PROGRAM(
      [[#include <hurd.h>
#define _STANDALONE
#include <rump/rump.h>]],
    [])],
    [HAVE_LIBRUMP_VFSNOFIFO=yes],
    [HAVE_LIBRUMP_VFSNOFIFO=no])
  AC_SUBST([HAVE_LIBRUMP_VFSNOFIFO])

  # Reset
  LIBS="$oldLIBS"
])

AC_ARG_ENABLE(boot-store-types,
[  --enable-boot-store-types=TYPES...
			  list of store types included in statically
			  linked filesystems used for booting])dnl
if test -z "$enable_boot_store_types"; then
  boot_store_types='device remap'
  test -z "$PARTED_LIBS" || boot_store_types="$boot_store_types part"
  test -z "$HAVE_LIBBZ2" || boot_store_types="$boot_store_types bunzip2"
  test -z "$HAVE_LIBZ"   || boot_store_types="$boot_store_types gunzip"
elif test "x$enable_boot_store_types" = xno; then
  AC_MSG_WARN([you probably wanted --disable-static-progs])
else
  boot_store_types="$enable_boot_store_types"
fi
AC_SUBST(boot_store_types)dnl
AC_MSG_CHECKING(boot store types)
AC_MSG_RESULT($boot_store_types)

# Check for ncursesw, which is needed for the console-curses client.
hurd_LIB_NCURSESW

# Check for xkbcommon, needed for keyboard mappings.
PKG_CHECK_MODULES([xkbcommon], [xkbcommon], [have_xkbcommon=yes], [have_xkbcommon=no])

AC_SUBST([have_xkbcommon])
AC_SUBST([xkbcommon_CFLAGS])
AC_SUBST([xkbcommon_LIBS])

# Check for Sun RPC headers and library.
AC_ARG_WITH([libtirpc],
  [AS_HELP_STRING([--without-libtirpc], [disable libtirpc use in nfs/nfsd])],
  [],
  [with_libtirpc=yes])

AS_IF([test "x$with_libtirpc" != xno], [
  PKG_CHECK_MODULES([libtirpc], [libtirpc], [HAVE_SUN_RPC=yes], [HAVE_SUN_RPC=no])
])
AC_SUBST([HAVE_SUN_RPC])
AC_SUBST([libtirpc_CFLAGS])
AC_SUBST([libtirpc_LIBS])

if test -f ./$ac_unique_file; then
  # Configuring in source directory; don't create any Makefiles.
  makefiles=
else
  # We are configuring in a separate build tree.
  # Create a Makefile in the top-level build directory and
  # one for each subdirectory Makefile in the source.
  makefiles="Makeconf:build.mkcf.in \
	     `cd $srcdir; for file in Makefile */Makefile; do \
			    echo ${file}:build.mk.in; done`"
fi

AC_ARG_WITH([libdaemon],
  [AS_HELP_STRING([--without-libdaemon], [disable libdaemon use in console client])],
  [],
  [with_libdaemon=yes])

AS_IF([test "x$with_libdaemon" != xno], [
  PKG_CHECK_MODULES([libdaemon], [libdaemon],
    [AC_DEFINE([HAVE_DAEMON], [1], [Use libdaemon])],
    [true])
])
AC_SUBST([libdaemon_LIBS])
AC_SUBST([libdaemon_CFLAGS])


AC_CHECK_MEMBERS([struct thread_sched_info.last_processor],,,
 [#include <mach/thread_info.h>])

AC_CHECK_MEMBERS([struct mapped_time_value.time_value.seconds],,,
 [#include <mach/time_value.h>])

PKG_CHECK_MODULES([libblkid], [blkid],
  [AC_DEFINE([HAVE_BLKID], [1], [Use libblkid])],
  [true])
AC_SUBST([libblkid_LIBS])
AC_SUBST([libblkid_CFLAGS])

PKG_CHECK_MODULES([libgcrypt], [libgcrypt], [HAVE_LIBGCRYPT=yes], [HAVE_LIBGCRYPT=no])
AC_SUBST([HAVE_LIBGCRYPT])
AC_SUBST([libgcrypt_LIBS])
AC_SUBST([libgcrypt_CFLAGS])

PKG_CHECK_MODULES([liblwip], [lwip], [HAVE_LIBLWIP=yes], [HAVE_LIBLWIP=no])
AC_SUBST([HAVE_LIBLWIP])
AC_SUBST([liblwip_CFLAGS])
AC_SUBST([liblwip_LIBS])

PKG_CHECK_MODULES([libpciaccess], [pciaccess], [HAVE_LIBPCIACCESS=yes], [HAVE_LIBPCIACCESS=no])
AC_SUBST([HAVE_LIBPCIACCESS])
AC_SUBST([libpciaccess_CFLAGS])
AC_SUBST([libpciaccess_LIBS])

AC_ARG_WITH([acpica],
  [AS_HELP_STRING([--without-acpica], [disable acpica])], , [with_acpica=yes])

AS_IF([test "x$with_acpica" != xno], [
  AC_CHECK_HEADER([acpi/acpi_init.h], [
    HAVE_LIBACPICA=yes
    libacpica_LIBS="-lacpica -lpciaccess"
    libacpica_CFLAGS=""],
    [HAVE_LIBACPICA=no])
])
AC_SUBST([HAVE_LIBACPICA])
AC_SUBST([libacpica_CFLAGS])
AC_SUBST([libacpica_LIBS])

AC_CONFIG_FILES([config.make ${makefiles} daemons/runsystem.hurd.sh])
AC_OUTPUT

dnl Local Variables:
dnl comment-start: "dnl "
dnl comment-end: ""
dnl comment-start-skip: "\\bdnl\\b\\s *"
dnl compile-command: "autoconf"
dnl End:
