/* MIG type translation information

   Copyright (C) 2017 Free Software Foundation, Inc.
   Written by Michael I. Bushnell, p/BSG.

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
   along with the GNU Hurd.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Only CPP macro definitions should go in this file. */

#define ACPI_IMPORTS			\
  import "../libnetfs/priv.h";		\

#define ACPI_INTRAN protid_t begin_using_protid_port (acpi_t)
#define ACPI_INTRAN_PAYLOAD protid_t begin_using_protid_payload
#define ACPI_DESTRUCTOR end_using_protid_port (protid_t)
