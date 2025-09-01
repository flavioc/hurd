/* Implementation of memory_object_data_return for pager library
   Copyright (C) 1994,95,96,99,2000,02 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA. */

#include "priv.h"
#include "memory_object_S.h"
#include <stdio.h>
#include <string.h>
#include <assert-backtrace.h>

/* Worker function used by _pager_S_memory_object_data_return
   and _pager_S_memory_object_data_initialize.  All args are
   as for _pager_S_memory_object_data_return; the additional
   INITIALIZING arg identifies which function is calling us. */
kern_return_t
_pager_do_write_request (struct pager *p,
			 mach_port_t control,
			 vm_offset_t offset,
			 pointer_t data,
			 vm_size_t length,
			 int dirty,
			 int kcopy,
			 int initializing)
{
  short *pm_entries;
  int npages, i;
  char *notified;
  error_t *pagerrs;
  struct lock_request *lr;
  struct lock_list {struct lock_request *lr;
		    struct lock_list *next;} *lock_list, *ll;
  int wakeup;
  unsigned omitdata = 0;

  if (!p
      || p->port.class != _pager_class)
    return EOPNOTSUPP;

  /* Acquire the right to meddle with the pagemap */
  pthread_mutex_lock (&p->interlock);

  /* sanity checks -- we don't do multi-page requests yet.  */
  if (control != p->memobjcntl)
    {
      printf ("incg data return: wrong control port\n");
      goto release_out;
    }
  if (length % __vm_page_size)
    {
      printf ("incg data return: bad length size %lu\n", (unsigned long)length);
      goto release_out;
    }
  if (offset % __vm_page_size)
    {
      printf ("incg data return: misaligned request\n");
      goto release_out;
    }

  if (p->pager_state != NORMAL)
    {
      printf ("pager in wrong state for write\n");
      goto release_out;
    }

  npages = length / __vm_page_size;
  pagerrs = alloca (npages * sizeof (error_t));

  notified = alloca (npages * (sizeof *notified));
#ifndef NDEBUG
  memset (notified, -1, npages * (sizeof *notified));
#endif

  _pager_block_termination (p);	/* until we are done with the pagemap
				   when the write completes. */

  _pager_pagemap_resize (p, offset + length);

  pm_entries = &p->pagemap[offset / __vm_page_size];

  if (! dirty)
    {
      munmap ((void *) data, length);
      if (!kcopy) {
        /* Prepare notified array.  */
        for (i = 0; i < npages; i++)
          notified[i] = (p->notify_on_evict
                         && ! (pm_entries[i] & PM_PAGEINWAIT));

        goto notify;
      }
      else {
        _pager_allow_termination (p);
        goto release_out;
      }
    }

  /* Make sure there are no other in-progress writes for any of these
     pages before we begin.  This imposes a little more serialization
     than we really have to require (because *all* future writes on
     this object are going to wait for seqno while we wait for the
     previous write), but the case is relatively infrequent.  */
  /* XXX: Is this still needed?  */
 retry:
  for (i = 0; i < npages; i++)
    if (pm_entries[i] & PM_PAGINGOUT)
      {
	pm_entries[i] |= PM_WRITEWAIT;
	pthread_cond_wait (&p->wakeup, &p->interlock);
	goto retry;
      }

  /* Mark these pages as being paged out.  */
  if (initializing)
    {
      assert_backtrace (npages < 32);
      for (i = 0; i < npages; i++)
	{
	  if (pm_entries[i] & PM_INIT)
	    omitdata |= 1U << i;
	  else
	    pm_entries[i] |= PM_PAGINGOUT | PM_INIT;
	}
    }
  else
    for (i = 0; i < npages; i++)
      pm_entries[i] |= PM_PAGINGOUT | PM_INIT;

  /* If this write occurs while a lock is pending, record
     it.  We have to keep this list because a lock request
     might come in while we do the I/O; in that case there
     would be a new entry on p->lock_requests and we must
     make sure we don't decrement it.  So we have to keep
     track independently of which lock requests we incremented. */
  lock_list = 0;
  for (lr = p->lock_requests; lr; lr = lr->next)
    if (offset < lr->end && offset + length >= lr->start)
      {
	ll = alloca (sizeof (struct lock_list));
	ll->lr = lr;
	ll->next = lock_list;
	lock_list = ll;
	lr->pending_writes++;
      }

  /* Let someone else in. */
  pthread_mutex_unlock (&p->interlock);

  int i_page = 0;
  while (i_page < npages)
    {
      if (omitdata & (1U << i_page))
	{
	  i_page++;
	  continue;
	}

      /* Find maximal contiguous run [i_page, j_page) with no omitdata.  */
      int j_page = i_page + 1;
      while (j_page < npages && ! (omitdata & (1U << j_page)))
	j_page++;

      vm_offset_t run_off = offset + (vm_page_size * i_page);
      vm_address_t run_ptr = data + (vm_page_size * i_page);
      vm_size_t run_len = vm_page_size * (j_page - i_page);

      vm_size_t wrote = 0;

      /* Attempt bulk write.  */
      error_t berr = pager_write_pages (p->upi, run_off, run_ptr,
					run_len, &wrote);

      /* How many pages did bulk actually complete? (only if not EOPNOTSUPP) */
      int pages_done = 0;
      if (berr != EOPNOTSUPP)
	{
	  if (wrote > run_len)
	    wrote = run_len;
	  wrote -= (wrote % vm_page_size);
	  pages_done = wrote / vm_page_size;
	}

      /* Mark successful prefix (if any).  */
      for (int k = 0; k < pages_done; k++)
	pagerrs[i_page + k] = 0;

      /* Per-page the remaining suffix of the run, or the whole run if unsupported.  */
      for (int k = i_page + pages_done; k < j_page; k++)
	  pagerrs[k] = pager_write_page (p->upi,
					 offset + (vm_page_size * k),
					 data + (vm_page_size * k));

      i_page = j_page;
    }


  /* Acquire the right to meddle with the pagemap */
  pthread_mutex_lock (&p->interlock);
  _pager_pagemap_resize (p, offset + length);
  pm_entries = &p->pagemap[offset / __vm_page_size];

  wakeup = 0;
  for (i = 0; i < npages; i++)
    {
      if (omitdata & (1U << i))
	{
	  notified[i] = 0;
	  continue;
	}

      if (pm_entries[i] & PM_WRITEWAIT)
	wakeup = 1;

      if (pagerrs[i] && ! (pm_entries[i] & PM_PAGEINWAIT))
	/* The only thing we can do here is mark the page, and give
	   errors from now on when it is to be read.  This is
	   imperfect, because if all users go away, the pagemap will
	   be freed, and this information lost.  Oh well.  It's still
	   better than Un*x.  Of course, if we are about to hand this
	   data to the kernel, the error isn't a problem, hence the
	   check for pageinwait.  */
	pm_entries[i] |= PM_INVALID;

      if (pm_entries[i] & PM_PAGEINWAIT)
	{
	  memory_object_data_supply (p->memobjcntl,
				     offset + (vm_page_size * i),
				     data + (vm_page_size * i),
				     vm_page_size, 1,
				     VM_PROT_NONE, 0, MACH_PORT_NULL);
	  notified[i] = 0;
	}
      else
	{
	  munmap ((void *) (data + (vm_page_size * i)),
		  vm_page_size);
	  notified[i] = (! kcopy && p->notify_on_evict);
	  if (! kcopy)
	    pm_entries[i] &= ~PM_INCORE;
	}

      pm_entries[i] &= ~(PM_PAGINGOUT | PM_PAGEINWAIT | PM_WRITEWAIT);
    }

  for (ll = lock_list; ll; ll = ll->next)
    if (!--ll->lr->pending_writes && !ll->lr->locks_pending)
      wakeup = 1;

  if (wakeup)
    pthread_cond_broadcast (&p->wakeup);

 notify:
  _pager_allow_termination (p);
  pthread_mutex_unlock (&p->interlock);

  for (i = 0; i < npages; i++)
    {
      assert_backtrace (notified[i] == 0 || notified[i] == 1);
      if (notified[i])
	{
	  short *pm_entry = &pm_entries[i];

	  /* Do notify user.  */
	  pager_notify_evict (p->upi, offset + (i * vm_page_size));

	  /* Clear any error that is left.  Notification on eviction
	     is used only to change association of page, so any
	     error may no longer be valid.  */
	  pthread_mutex_lock (&p->interlock);
	  *pm_entry = SET_PM_ERROR (SET_PM_NEXTERROR (*pm_entry, 0), 0);
	  pthread_mutex_unlock (&p->interlock);
	}
    }

  return 0;

 release_out:
  pthread_mutex_unlock (&p->interlock);
  return 0;
}

/* Implement pageout call back as described by <mach/memory_object.defs>. */
kern_return_t
_pager_S_memory_object_data_return (struct pager *p,
					 mach_port_t control,
					 vm_offset_t offset,
					 pointer_t data,
					 mach_msg_type_number_t length,
					 int dirty,
					 int kcopy)
{
  return _pager_do_write_request (p, control, offset, data,
				  length, dirty, kcopy, 0);
}
