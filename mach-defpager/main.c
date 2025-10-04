/* Main program for standalone Hurd version of Mach default pager.
   Copyright (C) 1999, 2001 Free Software Foundation, Inc.

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



#include <mach.h>
#include <hurd.h>
#include <pthread.h>
#include <device/device.h>
#include <device/device_types.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <error.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>

/* XXX */
#include <fcntl.h>
#include <paths.h>
#include <errno.h>
#include <unistd.h>
#include <hurd.h>
#include <hurd/port.h>
#include <hurd/fd.h>
#include <hurd/paths.h>
#include <hurd/startup.h>
#include <assert-backtrace.h>
/* XXX */

#include "default_pager.h"

const char *defpager_server_name = "mach-defpager";

mach_port_t	bootstrap_master_device_port;	/* local name */
mach_port_t	bootstrap_master_host_port;	/* local name */

static void
printf_init (device_t master)
{
  mach_port_t cons;
  kern_return_t rc;
  rc = device_open (master, D_READ|D_WRITE, "console", &cons);
  if (rc)
    error (2, rc, "cannot open kernel console device");
  stdin = mach_open_devstream (cons, "r");
  stdout = stderr = mach_open_devstream (cons, "w");
  mach_port_deallocate (mach_task_self (), cons);
  setlinebuf (stderr);
}


int debug;

static void
nohandler (int sig)
{ }

int
main (int argc, char **argv)
{
  const task_t my_task = mach_task_self();
  error_t err;
  memory_object_t defpager;

  err = get_privileged_ports (&bootstrap_master_host_port,
			      &bootstrap_master_device_port);
  if (err)
    error (1, err, "cannot get privileged ports");

  defpager = MACH_PORT_NULL;
  err = vm_set_default_memory_manager (bootstrap_master_host_port, &defpager);
  if (err)
    error (1, err, "cannot check current default memory manager");
  if (MACH_PORT_VALID (defpager))
    error (2, 0, "Another default memory manager is already running");

  if (!(argc == 2 && !strcmp (argv[1], "-d")))
    {
      /* We don't use the `daemon' function because we might exit back to the
	 parent before the daemon has completed vm_set_default_memory_manager.
	 Instead, the parent waits for a SIGUSR1 from the child before
	 exitting, and the child sends that signal after it is set up.  */
      sigset_t set;
      signal (SIGUSR1, nohandler);
      signal (SIGCHLD, nohandler);
      sigemptyset (&set);
      sigaddset (&set, SIGUSR1);
      sigaddset (&set, SIGCHLD);
      sigprocmask (SIG_SETMASK, &set, NULL);
      switch (fork ())
	{
	case -1:
	  error (1, errno, "cannot become daemon");
	case 0:
	  setsid ();
	  err = chdir ("/");
	  if (err == -1)
	    error (3, 0, "chdir call failed");
	  close (0);
	  close (1);
	  close (2);
	  break;
	default:
	  sigemptyset (&set);
	  sigsuspend (&set);
	  _exit (0);
	}
    }

  /* Mark us as important.  */
  mach_port_t proc = getproc ();
  if (proc == MACH_PORT_NULL)
    error (3, err, "cannot get a handle to our process");

  err = proc_mark_important (proc);
  /* This might fail due to permissions or because the old proc server
     is still running, ignore any such errors.  */
  if (err && err != EPERM && err != EMIG_BAD_ID)
    error (3, err, "cannot mark us as important");

  mach_port_deallocate (mach_task_self (), proc);

  /* Mark us as essential.  */
  mach_port_t startup;
  startup = file_name_lookup (_SERVERS_STARTUP, 0, 0);
  if (startup == MACH_PORT_NULL)
    error (0, errno, "WARNING: Cannot register as essential task\n");

  startup_essential_task (startup, mach_task_self (), MACH_PORT_NULL,
			  program_invocation_short_name,
			  bootstrap_master_host_port);

  mach_port_deallocate (mach_task_self (), startup);

  printf_init(bootstrap_master_device_port);

  /*
   * Set up the default pager.
   */
  partition_init();

  /*
   * task_set_exception_port and task_set_bootstrap_port
   * both require a send right.
   */
  (void) mach_port_insert_right(my_task, default_pager_exception_port,
				default_pager_exception_port,
				MACH_MSG_TYPE_MAKE_SEND);

  /*
   * Change our exception port.
   */
  if (!debug)
  (void) task_set_exception_port(my_task, default_pager_exception_port);

  default_pager_initialize (bootstrap_master_host_port);

  if (!(argc == 2 && !strcmp (argv[1], "-d")))
    kill (getppid (), SIGUSR1);

  /*
   * Become the default pager
   */
  default_pager();
  /*NOTREACHED*/
  return -1;
}


void
panic (const char *fmt, ...)
{
  va_list ap;
  fprintf (stderr, "%s: panic: ", program_invocation_name);
  va_start (ap, fmt);
  vfprintf (stderr, fmt, ap);
  va_end (ap);
  assert_backtrace (0);
}
