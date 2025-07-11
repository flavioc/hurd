/* Hurd /proc filesystem, permanent files of the root directory.
   Copyright (C) 2010,13,14,17 Free Software Foundation, Inc.

   This file is part of the GNU Hurd.

   The GNU Hurd is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   The GNU Hurd is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA. */

#include <mach/gnumach.h>
#include <mach/vm_param.h>
#include <mach/vm_statistics.h>
#include <mach/vm_cache_statistics.h>
#include "default_pager_U.h"
#include <mach_debug/mach_debug_types.h>
#include <hurd/paths.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <argz.h>
#include <ps.h>
#include <glob.h>
#include "procfs.h"
#include "procfs_dir.h"
#include "main.h"
#include <net/route.h>
#if defined (__x86_64__) || defined (__i486__) || defined (__i586__) || defined (__i686__)
#include <cpuid.h>
#elif defined (__aarch64__)
#warning Aarch64 port of cpuinfo is untested
#include <mach/machine/mach_aarch64.h>
#endif

#include "mach_debug_U.h"
#include "pfinet_U.h"

#define ROUTE_STRLEN 180

/* This implements a directory node with the static files in /proc.
   NB: the libps functions for host information return static storage;
   using them would require locking and as a consequence it would be
   more complicated, not simpler.  */


/* Helper functions */

/* We get the boot time by using that of the kernel process. */
static error_t
get_boottime (struct ps_context *pc, struct timeval *tv)
{
  struct proc_stat *ps;
  error_t err;

  err = _proc_stat_create (opt_kernel_pid, pc, &ps);
  if (err)
    return err;

  err = proc_stat_set_flags (ps, PSTAT_TASK_BASIC);
  if (err || !(proc_stat_flags (ps) & PSTAT_TASK_BASIC))
    err = EIO;

  if (! err)
    {
      task_basic_info_t tbi = proc_stat_task_basic_info (ps);
      tv->tv_sec = tbi->creation_time.seconds;
      tv->tv_usec = tbi->creation_time.microseconds;
    }

  _proc_stat_free (ps);
  return err;
}

/* We get the idle time for cpu_number by querying the kernel's idle threads. */
static error_t
get_idletime (struct ps_context *pc, struct timeval *tv, int cpu_number)
{
  struct proc_stat *ps, *pst;
  thread_basic_info_t tbi;
  thread_sched_info_t tsi;
  error_t err;
  int i;

  err = _proc_stat_create (opt_kernel_pid, pc, &ps);
  if (err)
    return err;

  pst = NULL, tbi = NULL, tsi = NULL;

  err = proc_stat_set_flags (ps, PSTAT_NUM_THREADS);
  if (err || !(proc_stat_flags (ps) & PSTAT_NUM_THREADS))
    {
      err = EIO;
      goto out;
    }

  /* Look for the idle thread for cpu_number */
  for (i=0; !tbi || !tsi
   || !(tbi->flags & TH_FLAGS_IDLE)
   || !(tsi->last_processor == cpu_number); i++)
    {
      if (pst)
	_proc_stat_free (pst);

      pst = NULL, tbi = NULL, tsi = NULL;
      if (i >= proc_stat_num_threads (ps))
	{
	  err = ESRCH;
	  goto out;
	}

      err = proc_stat_thread_create (ps, i, &pst);
      if (err)
	continue;

      err = proc_stat_set_flags (pst, PSTAT_THREAD_BASIC);
      if (err || ! (proc_stat_flags (pst) & PSTAT_THREAD_BASIC))
	continue;

      tbi = proc_stat_thread_basic_info (pst);

      err = proc_stat_set_flags (pst, PSTAT_THREAD_SCHED);
      if (err || ! (proc_stat_flags (pst) & PSTAT_THREAD_SCHED))
	continue;

      tsi = proc_stat_thread_sched_info (pst);
    }

  /* We found it! */
  tv->tv_sec = tbi->system_time.seconds;
  tv->tv_usec = tbi->system_time.microseconds;
  err = 0;

out:
  if (pst) _proc_stat_free (pst);
  _proc_stat_free (ps);
  return err;
}

static error_t
get_swapinfo (default_pager_info_t *info)
{
  mach_port_t defpager;
  error_t err;

  defpager = file_name_lookup (_SERVERS_DEFPAGER, O_READ, 0);
  if (defpager == MACH_PORT_NULL)
    return errno;

  err = default_pager_info (defpager, info);
  mach_port_deallocate (mach_task_self (), defpager);

  return err;
}


/* Content generators */

static error_t
rootdir_gc_version (void *hook, char **contents, ssize_t *contents_len)
{
  struct utsname uts;
  int r;

  r = uname (&uts);
  if (r < 0)
    return errno;

  *contents_len = asprintf (contents,
      "Linux version 2.6.1 (%s %s %s %s)\n",
      uts.sysname, uts.release, uts.version, uts.machine);

  return 0;
}

static error_t
rootdir_gc_uptime (void *hook, char **contents, ssize_t *contents_len)
{
  struct timeval time, boottime, idletime;
  double up_secs, idle_secs;
  error_t err;

  err = gettimeofday (&time, NULL);
  if (err < 0)
    return errno;

  err = get_boottime (hook, &boottime);
  if (err)
    return err;

  err = get_idletime (hook, &idletime, 0);
  if (err)
    return err;

  timersub (&time, &boottime, &time);
  up_secs = (time.tv_sec * 1000000. + time.tv_usec) / 1000000.;
  idle_secs = (idletime.tv_sec * 1000000. + idletime.tv_usec) / 1000000.;

  /* The second field is the total idle time. As far as I know we don't
     keep track of it.  However, procps uses it to compute "USER_HZ", and
     proc(5) specifies that it should be equal to USER_HZ times the idle value
     in ticks from /proc/stat.  So we assume a completely idle system both here
     and there to make that work.  */
  *contents_len = asprintf (contents, "%.2lf %.2lf\n", up_secs, idle_secs);

  return 0;
}

static error_t
rootdir_gc_stat (void *hook, char **contents, ssize_t *contents_len)
{
  struct timeval boottime, time, idletime;
  struct vm_statistics vmstats;
  unsigned long up_ticks, idle_ticks;
  int i;
  FILE *m;
  host_basic_info_t basic;
  error_t err;

  err = ps_host_basic_info (&basic);
  if (err)
    return EIO;

  err = gettimeofday (&time, NULL);
  if (err < 0)
    return errno;

  err = get_boottime (hook, &boottime);
  if (err)
    return err;

  err = get_idletime (hook, &idletime, 0);
  if (err)
    return err;

  err = vm_statistics (mach_task_self (), &vmstats);
  if (err)
    return EIO;

  m = open_memstream (contents, (size_t *) contents_len);
  if (m == NULL)
    {
      err = ENOMEM;
      goto out;
    }

  timersub (&time, &boottime, &time);
  up_ticks = opt_clk_tck * (time.tv_sec * 1000000. + time.tv_usec) / 1000000.;
  idle_ticks = opt_clk_tck * (idletime.tv_sec * 1000000. + idletime.tv_usec) / 1000000.;

  fprintf (m,
      "cpu  %lu 0 0 %lu 0 0 0 0 0\n"
      "cpu0 %lu 0 0 %lu 0 0 0 0 0\n",
      up_ticks - idle_ticks, idle_ticks,
      up_ticks - idle_ticks, idle_ticks);

  for (i = 1; i < basic->avail_cpus; i++)
    {
      err = get_idletime (hook, &idletime, i);
      idle_ticks = opt_clk_tck * (idletime.tv_sec * 1000000. + idletime.tv_usec) / 1000000.;
      fprintf (m,
          "cpu%d %lu 0 0 %lu 0 0 0 0 0\n",
          i, up_ticks - idle_ticks, idle_ticks);
    }

  fprintf (m,
      "intr 0\n"
      "page %d %d\n"
      "btime %lu\n",
      vmstats.pageins, vmstats.pageouts,
      boottime.tv_sec);

 out:
  if (m)
    fclose (m);
  return err;
}

static error_t
rootdir_gc_loadavg (void *hook, char **contents, ssize_t *contents_len)
{
  host_load_info_data_t hli;
  mach_msg_type_number_t cnt;
  error_t err;

  cnt = HOST_LOAD_INFO_COUNT;
  err = host_info (mach_host_self (), HOST_LOAD_INFO, (host_info_t) &hli, &cnt);
  if (err)
    return err;

  assert_backtrace (cnt == HOST_LOAD_INFO_COUNT);
  *contents_len = asprintf (contents,
      "%.2f %.2f %.2f 1/0 0\n",
      hli.avenrun[0] / (double) LOAD_SCALE,
      hli.avenrun[1] / (double) LOAD_SCALE,
      hli.avenrun[2] / (double) LOAD_SCALE);

  return 0;
}

static error_t
rootdir_gc_meminfo (void *hook, char **contents, ssize_t *contents_len)
{
  host_basic_info_data_t hbi;
  mach_msg_type_number_t cnt;
  struct vm_statistics vmstats;
  struct vm_cache_statistics cache_stats;
  default_pager_info_t swap;
  FILE *m;
  error_t err;

  m = open_memstream (contents, (size_t *) contents_len);
  if (m == NULL)
    {
      err = ENOMEM;
      goto out;
    }

  err = vm_statistics (mach_task_self (), &vmstats);
  if (err)
    {
      err = EIO;
      goto out;
    }

  err = vm_cache_statistics (mach_task_self (), &cache_stats);
  if (err)
    {
      err = EIO;
      goto out;
    }

  cnt = HOST_BASIC_INFO_COUNT;
  err = host_info (mach_host_self (), HOST_BASIC_INFO, (host_info_t) &hbi, &cnt);
  if (err)
    goto out;

  assert_backtrace (cnt == HOST_BASIC_INFO_COUNT);
  fprintf (m,
      "MemTotal: %14llu kB\n"
      "MemFree:  %14llu kB\n"
      "Buffers:  %14llu kB\n"
      "Cached:   %14llu kB\n"
      "Active:   %14llu kB\n"
      "Inactive: %14llu kB\n"
      "Mlocked:  %14llu kB\n"
      ,
      (long long unsigned) (vmstats.free_count +
		            vmstats.active_count +
		            vmstats.inactive_count +
		            vmstats.wire_count) * PAGE_SIZE / 1024,
      (long long unsigned) vmstats.free_count * PAGE_SIZE / 1024,
      0ULL,
      (long long unsigned) cache_stats.cache_count * PAGE_SIZE / 1024,
      (long long unsigned) vmstats.active_count * PAGE_SIZE / 1024,
      (long long unsigned) vmstats.inactive_count * PAGE_SIZE / 1024,
      (long long unsigned) vmstats.wire_count * PAGE_SIZE / 1024);

  err = get_swapinfo (&swap);
  if (err)
    /* This is not fatal, we just omit the information.  */
    err = 0;
  else
    fprintf (m,
      "SwapTotal:%14llu kB\n"
      "SwapFree: %14llu kB\n"
      ,
      (long long unsigned) swap.dpi_total_space / 1024,
      (long long unsigned) swap.dpi_free_space / 1024);

 out:
  if (m)
    fclose (m);
  return err;
}

static error_t
rootdir_gc_vmstat (void *hook, char **contents, ssize_t *contents_len)
{
  struct vm_statistics vmstats;
  error_t err;

  err = vm_statistics (mach_task_self (), &vmstats);
  if (err)
    return EIO;

  *contents_len = asprintf (contents,
      "nr_free_pages %lu\n"
      "nr_inactive_anon %lu\n"
      "nr_active_anon %lu\n"
      "nr_inactive_file %lu\n"
      "nr_active_file %lu\n"
      "nr_unevictable %lu\n"
      "nr_mlock %lu\n"
      "pgpgin %lu\n"
      "pgpgout %lu\n"
      "pgfault %lu\n",
      (long unsigned) vmstats.free_count,
      /* FIXME: how can we distinguish the anon/file pages? Maybe we can
         ask the default pager how many it manages? */
      (long unsigned) vmstats.inactive_count,
      (long unsigned) vmstats.active_count,
      (long unsigned) 0,
      (long unsigned) 0,
      (long unsigned) vmstats.wire_count,
      (long unsigned) vmstats.wire_count,
      (long unsigned) vmstats.pageins,
      (long unsigned) vmstats.pageouts,
      (long unsigned) vmstats.faults);

  return 0;
}

static error_t
rootdir_gc_cmdline (void *hook, char **contents, ssize_t *contents_len)
{
  struct ps_context *pc = hook;
  struct proc_stat *ps;
  error_t err;

  err = _proc_stat_create (opt_kernel_pid, pc, &ps);
  if (err)
    return EIO;

  err = proc_stat_set_flags (ps, PSTAT_ARGS);
  if (err || ! (proc_stat_flags (ps) & PSTAT_ARGS))
    {
      err = EIO;
      goto out;
    }

  *contents_len = proc_stat_args_len (ps);
  *contents = malloc (*contents_len);
  if (! *contents)
    {
      err = ENOMEM;
      goto out;
    }

  memcpy (*contents, proc_stat_args (ps), *contents_len);
  argz_stringify (*contents, *contents_len, ' ');
  (*contents)[*contents_len - 1] = '\n';

out:
  _proc_stat_free (ps);
  return err;
}

static error_t
rootdir_gc_route (void *hook, char **contents, ssize_t *contents_len)
{
  error_t err;
  mach_port_t pfinet;
  unsigned int i, len, buflen = 0;
  char *src, *dst;
  ifrtreq_t *r;
  char dest[INET_ADDRSTRLEN], gw[INET_ADDRSTRLEN], mask[INET_ADDRSTRLEN];
  char socket_inet[20];

  char *inet_to_str(in_addr_t addr)
  {
    struct in_addr sin;

    sin.s_addr = addr;
    return inet_ntoa(sin);
  }

  snprintf(socket_inet, sizeof(socket_inet), _SERVERS_SOCKET "/%d", AF_INET);
  pfinet = file_name_lookup (socket_inet, O_RDONLY, 0);
  if (pfinet == MACH_PORT_NULL)
    {
      *contents_len = 0;
      return errno;
    }

  err = pfinet_getroutes (pfinet, -1, &src, &buflen);
  if (err)
    {
      *contents_len = 0;
      goto out;
    }

  r = (ifrtreq_t *)src;
  *contents_len = (buflen / sizeof(ifrtreq_t) + 1) * ROUTE_STRLEN;
  *contents = calloc (1, *contents_len);
  if (! *contents)
    {
      err = ENOMEM;
      goto out;
    }

  dst = *contents;
  snprintf(dst, ROUTE_STRLEN, "%-*s\n", ROUTE_STRLEN - 2, "Iface\tDestination\tGateway\t Flags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT");
  dst += ROUTE_STRLEN;

  for (i = 0; i < buflen / sizeof(ifrtreq_t); i++)
    {
      snprintf(dest, INET_ADDRSTRLEN, "%-*s", INET_ADDRSTRLEN - 1, inet_to_str(r->rt_dest));
      snprintf(gw,   INET_ADDRSTRLEN, "%-*s", INET_ADDRSTRLEN - 1, inet_to_str(r->rt_gateway));
      snprintf(mask, INET_ADDRSTRLEN, "%-*s", INET_ADDRSTRLEN - 1, inet_to_str(r->rt_mask));

      len = snprintf(dst, ROUTE_STRLEN, "%s\t%s\t%s\t%04X\t%d\t%u\t%d\t%s\t%d\t%u\t%u\n",
		     r->ifname, dest, gw, r->rt_flags, 0, 0,
		     r->rt_metric, mask, r->rt_mtu, r->rt_window, r->rt_irtt);
      dst += len;
      r++;
    }

out:
  mach_port_deallocate (mach_task_self (), pfinet);
  return err;
}

static struct node *rootdir_self_node;
static struct node *rootdir_mounts_node;

static error_t
rootdir_gc_slabinfo (void *hook, char **contents, ssize_t *contents_len)
{
  error_t err;
  FILE *m;
  const char header[] =
    "cache                          obj slab  bufs   objs   bufs"
    "    total reclaimable\n"
    "name                  flags   size size /slab  usage  count"
    "   memory      memory\n";
  cache_info_array_t cache_info;
  size_t mem_usage, mem_reclaimable, mem_total, mem_total_reclaimable;
  mach_msg_type_number_t cache_info_count;
  int i;

  cache_info = NULL;
  cache_info_count = 0;

  err = host_slab_info (mach_host_self(), &cache_info, &cache_info_count);
  if (err)
    return err;

  m = open_memstream (contents, (size_t *) contents_len);
  if (m == NULL)
    {
      err = ENOMEM;
      goto out;
    }

  fprintf (m, "%s", header);

  mem_total = 0;
  mem_total_reclaimable = 0;

  for (i = 0; i < cache_info_count; i++)
    {
      mem_usage =
	(cache_info[i].nr_slabs * cache_info[i].slab_size) >> 10;
      mem_total += mem_usage;
      mem_reclaimable =
	(cache_info[i].nr_free_slabs * cache_info[i].slab_size) >> 10;
      mem_total_reclaimable += mem_reclaimable;
      fprintf (m,
               "%-21s %04x %7zu %3zuk  %4lu %6lu %6lu %7zuk %10zuk\n",
               cache_info[i].name, cache_info[i].flags,
               cache_info[i].obj_size, cache_info[i].slab_size >> 10,
               cache_info[i].bufs_per_slab, cache_info[i].nr_objs,
               cache_info[i].nr_bufs, mem_usage, mem_reclaimable);
    }

  fprintf (m, "total: %zuk, reclaimable: %zuk\n",
           mem_total, mem_total_reclaimable);

  fclose (m);

 out:
  vm_deallocate (mach_task_self (), (vm_address_t) cache_info,
                 cache_info_count * sizeof *cache_info);
  return err;
}

static error_t
rootdir_gc_hostinfo (void *hook, char **contents, ssize_t *contents_len)
{
  error_t err;
  FILE *m;
  host_basic_info_t basic;
  host_sched_info_t sched;
  host_load_info_t load;

  m = open_memstream (contents, (size_t *) contents_len);
  if (m == NULL)
    return ENOMEM;

  err = ps_host_basic_info (&basic);
  if (! err)
    fprintf (m, "Basic info:\n"
             "max_cpus	= %10u	/* max number of cpus possible */\n"
             "avail_cpus	= %10u	/* number of cpus now available */\n"
             "memory_size	= %10zu	/* size of memory in bytes */\n"
             "cpu_type	= %10u	/* cpu type */\n"
             "cpu_subtype	= %10u	/* cpu subtype */\n",
             basic->max_cpus,
             basic->avail_cpus,
             basic->memory_size,
             basic->cpu_type,
             basic->cpu_subtype);

  err = ps_host_sched_info (&sched);
  if (! err)
    fprintf (m, "\nScheduling info:\n"
             "min_timeout	= %10u	/* minimum timeout in milliseconds */\n"
             "min_quantum	= %10u	/* minimum quantum in milliseconds */\n",
             sched->min_timeout,
             sched->min_quantum);

  err = ps_host_load_info (&load);
  if (! err)
    fprintf (m, "\nLoad info:\n"
             "avenrun[3]	= { %.2f, %.2f, %.2f }\n"
             "mach_factor[3]	= { %.2f, %.2f, %.2f }\n",
             load->avenrun[0] / (double) LOAD_SCALE,
             load->avenrun[1] / (double) LOAD_SCALE,
             load->avenrun[2] / (double) LOAD_SCALE,
             load->mach_factor[0] / (double) LOAD_SCALE,
             load->mach_factor[1] / (double) LOAD_SCALE,
             load->mach_factor[2] / (double) LOAD_SCALE);

  fclose (m);
  return 0;
}

static error_t
rootdir_gc_filesystems (void *hook, char **contents, ssize_t *contents_len)
{
  error_t err = 0;
  size_t i;
  int glob_ret;
  glob_t matches;
  FILE *m;

  m = open_memstream (contents, (size_t *) contents_len);
  if (m == NULL)
    return errno;

  glob_ret = glob (_HURD "*fs", 0, NULL, &matches);
  switch (glob_ret)
    {
    case 0:
      for (i = 0; i < matches.gl_pathc; i++)
	{
	  /* Get ith entry, shave off the prefix.  */
	  char *name = &matches.gl_pathv[i][sizeof _HURD - 1];

	  /* Linux naming convention is a bit inconsistent.  */
	  if (strncmp (name, "ext", 3) == 0
	      || strcmp (name, "procfs") == 0)
	    /* Drop the fs suffix.  */
	    name[strlen (name) - 2] = 0;

	  fprintf (m, "\t%s\n", name);
	}

      globfree (&matches);
      break;

    case GLOB_NOMATCH:
      /* Poor fellow.  */
      break;

    case GLOB_NOSPACE:
      err = ENOMEM;
      break;

    default:
      /* This should not happen.  */
      err = EGRATUITOUS;
    }

  fclose (m);
  return err;
}

static error_t
rootdir_gc_swaps (void *hook, char **contents, ssize_t *contents_len)
{
  mach_port_t defpager;
  error_t err = 0;
  FILE *m;
  vm_size_t *free = NULL;
  mach_msg_type_number_t nfree = 0;
  vm_size_t *size = NULL;
  mach_msg_type_number_t nsize = 0;
  char *names = NULL, *name;
  mach_msg_type_number_t names_len = 0;
  size_t i;

  m = open_memstream (contents, (size_t *) contents_len);
  if (m == NULL)
    return errno;

  defpager = file_name_lookup (_SERVERS_DEFPAGER, O_READ, 0);
  if (defpager == MACH_PORT_NULL)
    {
      err = errno;
      goto out_fclose;
    }

  err = default_pager_storage_info (defpager, &size, &nsize, &free, &nfree,
				    &names, &names_len);
  if (err)
    goto out;

  fprintf(m, "Filename\tType\t\tSize\tUsed\tPriority\n");
  name = names;
  for (i = 0; i < nfree; i++)
    {
      fprintf (m, "%s\tpartition\t%zu\t%zu\t-1\n",
	       name, size[i] >> 10, (size[i] - free[i]) >> 10);
      name = argz_next (names, names_len, name);
    }

  vm_deallocate (mach_task_self(), (vm_offset_t) free, nfree * sizeof (*free));
  vm_deallocate (mach_task_self(), (vm_offset_t) size, nsize * sizeof (*size));
  vm_deallocate (mach_task_self(), (vm_offset_t) names, names_len);

out:
  mach_port_deallocate (mach_task_self (), defpager);
out_fclose:
  fclose (m);
  return err;
}

#if defined (__x86_64__) || defined (__i486__) || defined (__i586__) || defined (__i686__)
static char *cpu_features_edx[] =
  {
    "fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce", "cx8", "apic",
    NULL, "sep", "mtrr", "pge", "mca", "cmov", "pat", "pse36", "pn", "clflush",
    NULL, "dts", "acpi", "mmx", "fxsr", "sse", "sse2", "ss", "ht", "tm",
    "ia64", "pbe"
  };

static char *cpu_features_ecx[] =
  {
    "sse3", "pclmulqdq", "dtes64", "monitor", "ds_cpl", "vmx", "smx", "est",
    "tm2", "ssse3", "cid", "sdbg", "fma", "cx16", "xtpr", "pdcm",
    NULL, "pcid", "dca", "sse4_1", "sse4_2", "x2apic", "movbe", "popcnt",
    "tsc_deadline_timer", "aes", "xsave", "osxsave", "avx", "f16c", "rdrand", "hypervisor"
  };

#define VENDOR_ID_LEN  12
#define MODEL_NAME_LEN 48

static error_t
cpuinfo_x86 (void* hook, char **contents, ssize_t *contents_len)
{
  error_t err = 0;
  FILE* m;
  int ret, index, stepping, model, family, extended_model, extended_family;
  unsigned int eax, ebx, ecx, edx;
  unsigned int feature_edx, feature_ecx;
  char vendor[VENDOR_ID_LEN + 1] = { 0 };
  char model_name[MODEL_NAME_LEN + 1] = { 0 };

  m = open_memstream (contents, (size_t *) contents_len);
  if (m == NULL)
    return errno;

  ret = __get_cpuid (0, &eax, &ebx, &ecx, &edx);
  if (ret != 1)
    {
      err = EIO;
      goto out;
    }

  memcpy (vendor + 0 * sizeof (unsigned int), &ebx, sizeof (unsigned int));
  memcpy (vendor + 1 * sizeof (unsigned int), &edx, sizeof (unsigned int));
  memcpy (vendor + 2 * sizeof (unsigned int), &ecx, sizeof (unsigned int));

  ret = __get_cpuid (1, &eax, &ebx, &ecx, &edx);
  if (ret != 1)
    {
      err = EIO;
      goto out;
    }

  feature_edx = edx;
  feature_ecx = ecx;
  stepping = eax & 0x0F;
  model = (eax & 0xF0) >> 4;
  family = (eax & 0xF00) >> 8;
  extended_model = (eax & 0xF0000) >> 16;
  extended_family = (eax &0xFF00000) >> 20;

  if (family == 6 || family == 15)
    model += (extended_model << 4);
  if (family == 15)
    family += extended_family;

  __get_cpuid (0x80000000, &eax, &ebx, &ecx, &edx);
  if (eax >= 0x80000004)
    {
      __get_cpuid (0x80000002, &eax, &ebx, &ecx, &edx);
      memcpy (model_name + 0 * sizeof (unsigned int), &eax, sizeof (unsigned int));
      memcpy (model_name + 1 * sizeof (unsigned int), &ebx, sizeof (unsigned int));
      memcpy (model_name + 2 * sizeof (unsigned int), &ecx, sizeof (unsigned int));
      memcpy (model_name + 3 * sizeof (unsigned int), &edx, sizeof (unsigned int));

      __get_cpuid (0x80000003, &eax, &ebx, &ecx, &edx);
      memcpy (model_name + 4 * sizeof (unsigned int), &eax, sizeof (unsigned int));
      memcpy (model_name + 5 * sizeof (unsigned int), &ebx, sizeof (unsigned int));
      memcpy (model_name + 6 * sizeof (unsigned int), &ecx, sizeof (unsigned int));
      memcpy (model_name + 7 * sizeof (unsigned int), &edx, sizeof (unsigned int));

      __get_cpuid (0x80000004, &eax, &ebx, &ecx, &edx);
      memcpy (model_name + 8 * sizeof (unsigned int), &eax, sizeof (unsigned int));
      memcpy (model_name + 9 * sizeof (unsigned int), &ebx, sizeof (unsigned int));
      memcpy (model_name + 10 * sizeof (unsigned int), &ecx, sizeof (unsigned int));
      memcpy (model_name + 11 * sizeof (unsigned int), &edx, sizeof (unsigned int));
    }

  fprintf (m,
    "processor\t: 0\n"
    "vendor_id\t: %s\n"
    "cpu family\t: %d\n"
    "model\t\t: %d\n"
    "model name\t: %s\n"
    "stepping\t: %d\n",
    vendor, family, model, model_name, stepping);

  fprintf (m, "flags\t\t:");
  for (index = 0; index < (sizeof (cpu_features_edx)/sizeof (char*)); index++)
    {
      if (cpu_features_edx[index] == NULL)
        continue;
      if (feature_edx & (1ul << index))
        fprintf (m, " %s", cpu_features_edx[index]);
    }
  for (index = 0; index < (sizeof (cpu_features_ecx)/sizeof (char*)); index++)
    {
      if (cpu_features_ecx[index] == NULL)
        continue;
      if (feature_ecx & (1ul << index))
        fprintf (m, " %s", cpu_features_ecx[index]);
    }

  fprintf (m, "\n\n");

out:
  fclose (m);
  return err;
}
#endif

#if defined (__aarch64__)

static char *cpu_features_1[] =
  {
    "fp", "asimd", "evtstrm", "aes", "pmul", "sha1", "sha2", "crc32",
    "atomics", "fphp", "asimdhp", "cpuid", "asimdrdm", "jscvt", "fcma", "lrcpc",
    "dcpop", "sha3", "sm3", "sm4", "asimddp", "sha512", "sve", "asimdfhm",
    "dit", "uscat", "ilrcpc", "flagm", "ssbs", "sb", "paca", "pacg"
  };

static char *cpu_features_2[] =
  {
    "dcpodp", "sve2", "sveaes", "svepmull", "svebitperm", "svesha3", "svesm4", "flagm2",
    "frint", "svei8mm", "svef32mm", "svef64mm", "svebf16", "i8mm", "bf16", "dgh",
    "rng", "bti", "mie", "ecv", "afp", "rpres", "mte3", "sme",
    "sme_i16i64", "sme_f64f64", "sme_i8i32", "sme_f16f32", "sme_b16f32", "sme_f32f32", "sme_fa64", "wfxt",
    "ebf16", "sve_ebf16", "cssc", "rprfm", "sve2p1", "sme2", "sme2p1", "sme_i15i32",
    "sme_bi32i32", "sme_b16b16", "sme_f16f16", "mops", "hbc", "sve_b16b16", "lrcpc3", "lse123"
  };

static error_t
cpuinfo_aarch64 (void *hook, char **contents, ssize_t *contents_len)
{
  error_t err = 0;
  hwcaps_t caps;
  uint64_t midr, revidr;
  int index;
  unsigned int implementer, variant, architecture, part_num, revision;
  FILE *m;

  m = open_memstream (contents, (size_t *) contents_len);
  if (m == NULL)
    return errno;

  err = aarch64_get_hwcaps (mach_host_self (), &caps, &midr, &revidr);
  if (err)
    goto out;

  implementer  = (midr & 0xff000000) >> 24;
  variant      = (midr & 0x00f00000) >> 20;
  architecture = (midr & 0x000f0000) >> 16;
  part_num     = (midr & 0x0000fff0) >>  4;
  revision     = (midr & 0x0000000f) >>  0;

  fprintf (m, "processor\t\t: 0\n");
  fprintf (m, "Features\t\t:");
  for (index = 0; index < (sizeof (cpu_features_1) / sizeof (char *)); index++)
    {
      if (cpu_features_1[index] == NULL)
        continue;
      if (caps[0] & (1ul << index))
        fprintf (m, " %s", cpu_features_1[index]);
    }
  for (index = 0; index < (sizeof (cpu_features_2) / sizeof (char *)); index++)
    {
      if (cpu_features_2[index] == NULL)
        continue;
      if (caps[1] & (1ul << index))
        fprintf (m, " %s", cpu_features_2[index]);
    }
  fprintf (m, "\n");
  fprintf (m, "CPU implementer\t\t: 0x%x\n", implementer);
  fprintf (m, "CPU architecture\t: %d\n", architecture);
  fprintf (m, "CPU variant\t\t: 0x%x\n", variant);
  fprintf (m, "CPU part\t\t: 0x%x\n", part_num);
  fprintf (m, "CPU revision\t\t: %d\n", revision);
  fprintf (m, "\n");
out:
  fclose (m);
  return err;
}
#endif

static error_t
rootdir_gc_cpuinfo (void *hook, char **contents, ssize_t *contents_len)
{
#if defined (__x86_64__) || defined (__i486__) || defined (__i586__) || defined (__i686__)
  return cpuinfo_x86 (hook, contents, contents_len);
#elif defined (__aarch64__)
  return cpuinfo_aarch64 (hook, contents, contents_len);
#else
  return ENOTSUP;
#endif
}

/* Glue logic and entries table */

static struct node *
rootdir_file_make_node (void *dir_hook, const void *entry_hook)
{
  /* The entry hook we use is actually a procfs_node_ops for the file to be
     created.  The hook associated to these newly created files (and passed
     to the generators above as a consequence) is always the same global
     ps_context, which we get from rootdir_make_node as the directory hook. */
  return procfs_make_node (entry_hook, dir_hook);
}


/* Translator linkage.  */

static pthread_spinlock_t rootdir_translated_node_lock =
  PTHREAD_SPINLOCK_INITIALIZER;

struct procfs_translated_node_ops
{
  struct procfs_node_ops node_ops;

  struct node **npp;
  char *argz;
  size_t argz_len;
};

static struct node *
rootdir_make_translated_node (void *dir_hook, const void *entry_hook)
{
  const struct procfs_translated_node_ops *ops = entry_hook;
  struct node *np, *prev;

  pthread_spin_lock (&rootdir_translated_node_lock);
  np = *ops->npp;
  if (np != NULL)
    netfs_nref (np);
  pthread_spin_unlock (&rootdir_translated_node_lock);

  if (np != NULL)
    return np;

  np = procfs_make_node (entry_hook, (void *) entry_hook);
  if (np == NULL)
    return NULL;

  procfs_node_chtype (np, S_IFREG | S_IPTRANS);
  procfs_node_chmod (np, 0444);

  pthread_spin_lock (&rootdir_translated_node_lock);
  prev = *ops->npp;
  if (*ops->npp == NULL)
    *ops->npp = np;
  netfs_nref (*ops->npp);
  pthread_spin_unlock (&rootdir_translated_node_lock);

  if (prev != NULL)
    {
      netfs_nrele (np);
      np = prev;
    }

  return np;
}

static error_t
rootdir_translated_node_get_translator (void *hook, char **argz,
					mach_msg_type_number_t *argz_len)
{
  const struct procfs_translated_node_ops *ops = hook;

  *argz = malloc (ops->argz_len);
  if (! *argz)
    return ENOMEM;

  memcpy (*argz, ops->argz, ops->argz_len);
  *argz_len = ops->argz_len;
  return 0;
}

#define ROOTDIR_DEFINE_TRANSLATED_NODE(NPP, ARGZ)		  \
  &(struct procfs_translated_node_ops) {			  \
    .node_ops = {						  \
      .get_translator = rootdir_translated_node_get_translator,	  \
    },								  \
    .npp = NPP,							  \
    .argz = (ARGZ),						  \
    .argz_len = sizeof (ARGZ),					  \
  }

static const struct procfs_dir_entry rootdir_entries[] = {
  {
    .name = "self",
    .hook = ROOTDIR_DEFINE_TRANSLATED_NODE (&rootdir_self_node,
					    _HURD_MAGIC "\0pid"),
    .ops = {
      .make_node = rootdir_make_translated_node,
    }
  },
  {
    .name = "version",
    .hook = & (struct procfs_node_ops) {
      .get_contents = rootdir_gc_version,
      .cleanup_contents = procfs_cleanup_contents_with_free,
    },
  },
  {
    .name = "uptime",
    .hook = & (struct procfs_node_ops) {
      .get_contents = rootdir_gc_uptime,
      .cleanup_contents = procfs_cleanup_contents_with_free,
    },
  },
  {
    .name = "stat",
    .hook = & (struct procfs_node_ops) {
      .get_contents = rootdir_gc_stat,
      .cleanup_contents = procfs_cleanup_contents_with_free,
    },
  },
  {
    .name = "loadavg",
    .hook = & (struct procfs_node_ops) {
      .get_contents = rootdir_gc_loadavg,
      .cleanup_contents = procfs_cleanup_contents_with_free,
    },
  },
  {
    .name = "meminfo",
    .hook = & (struct procfs_node_ops) {
      .get_contents = rootdir_gc_meminfo,
      .cleanup_contents = procfs_cleanup_contents_with_free,
    },
  },
  {
    .name = "vmstat",
    .hook = & (struct procfs_node_ops) {
      .get_contents = rootdir_gc_vmstat,
      .cleanup_contents = procfs_cleanup_contents_with_free,
    },
  },
  {
    .name = "cmdline",
    .hook = & (struct procfs_node_ops) {
      .get_contents = rootdir_gc_cmdline,
      .cleanup_contents = procfs_cleanup_contents_with_free,
    },
  },
  {
    .name = "route",
    .hook = & (struct procfs_node_ops) {
      .get_contents = rootdir_gc_route,
      .cleanup_contents = procfs_cleanup_contents_with_free,
    },
  },
  {
    .name = "mounts",
    .hook = ROOTDIR_DEFINE_TRANSLATED_NODE (&rootdir_mounts_node,
					    _HURD_MTAB "\0/"),
    .ops = {
      .make_node = rootdir_make_translated_node,
    }
  },
  {
    .name = "slabinfo",
    .hook = & (struct procfs_node_ops) {
      .get_contents = rootdir_gc_slabinfo,
      .cleanup_contents = procfs_cleanup_contents_with_free,
    },
  },
  {
    .name = "hostinfo",
    .hook = & (struct procfs_node_ops) {
      .get_contents = rootdir_gc_hostinfo,
      .cleanup_contents = procfs_cleanup_contents_with_free,
    },
  },
  {
    .name = "filesystems",
    .hook = & (struct procfs_node_ops) {
      .get_contents = rootdir_gc_filesystems,
      .cleanup_contents = procfs_cleanup_contents_with_free,
    },
  },
  {
    .name = "swaps",
    .hook = & (struct procfs_node_ops) {
      .get_contents = rootdir_gc_swaps,
      .cleanup_contents = procfs_cleanup_contents_with_free,
    },
  },
  {
    .name = "cpuinfo",
    .hook = & (struct procfs_node_ops) {
      .get_contents = rootdir_gc_cpuinfo,
      .cleanup_contents = procfs_cleanup_contents_with_free,
    },
  },
#ifdef PROFILE
  /* In order to get a usable gmon.out file, we must apparently use exit(). */
  {
    .name = "exit",
    .ops = {
      .make_node = exit,
    },
  },
#endif
  {}
};

struct node
*rootdir_make_node (struct ps_context *pc)
{
  static const struct procfs_dir_ops ops = {
    .entries = rootdir_entries,
    .entry_ops = {
      .make_node = rootdir_file_make_node,
    },
  };
  return procfs_dir_make_node (&ops, pc);
}

