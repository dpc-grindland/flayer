
/*--------------------------------------------------------------------*/
/*--- Wrappers for tainting syscalls                               ---*/
/*---                                                 fl_syswrap.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Flayer, a heavyweight Valgrind tool for
   tracking marked/tainted data through memory.

   Copyright (C) 2006-2007 Google Inc. (Will Drewry)

   Based heavily on MemCheck by jseward@acm.org
   MemCheck: Copyright (C) 2000-2007 Julian Seward
   jseward@acm.org


   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#include "pub_tool_basics.h"
#include "pub_tool_vki.h"
#include "pub_tool_vkiscnums.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_machine.h"
#include "pub_tool_aspacemgr.h"
#include "pub_tool_threadstate.h"

#include "valgrind.h"

/* Pulled in to get the threadstate */
#include "pub_core_threadstate.h"
#include "fl_include.h"
#include "flayer.h"

#if defined(VGA_x86)
#  define GP_COUNT 8
#elif defined(VGA_amd64)
#  define GP_COUNT 16
#elif defined(VGA_ppc32) || defined(VGA_ppc64)
#  define GP_COUNT 34
#else
#  error Unknown arch
#endif
typedef
       struct {
         UWord args[GP_COUNT];
         UInt used;
       }
GuestArgs;



// VG_(N_THREADS) - do threads actually run concurrently here too?
static GuestArgs guest_args[VG_N_THREADS];

// Set up GuestArgs prior to arg_collector
static
void populate_guest_args(ThreadId tid)
{
  /* This is legacy.  I was using apply_GPs callback,
   * but it isn't threadsafe.  So for now, we bind to 
   * the ThreadState functions for the specific x86 arch
   */
  ThreadState *ts =  VG_(get_ThreadState) (tid);
  guest_args[tid].args[1] = ts->arch.vex.guest_ECX;
  guest_args[tid].args[2] = ts->arch.vex.guest_EDX;
  guest_args[tid].args[3] = ts->arch.vex.guest_EBX;
  guest_args[tid].args[4] = ts->arch.vex.guest_ESI;
  guest_args[tid].args[5] = ts->arch.vex.guest_EDI;
  guest_args[tid].args[6] = ts->arch.vex.guest_EBP;
  guest_args[tid].args[7] = ts->arch.vex.guest_EAX;
  guest_args[tid].used = 8;
}

void FL_(setup_guest_args)( void ) {
  VG_(memset)(&guest_args, 0, sizeof(guest_args));
}

#define MAX_PATH 256
static
void resolve_fd(UWord fd, Char *path, Int max) 
{
  Char src[MAX_PATH]; // be lazy and use their max
  Int len = 0;
  // TODO: Cache resolved fds by also catching open()s and close()s
  VG_(sprintf)(src, "/proc/%d/fd/%d", VG_(getpid)(), fd);
  len = VG_(readlink)(src, path, max);
  // Just give emptiness on error.
  if (len == -1) len = 0;
  path[len] = '\0';
}


// TODO: copy linked list setup for allocated_fds in clo_track_fds.
//       or see if they will patch it to allow tools to access it.
/* enforce an arbitrary maximum */
#define MAXIMUM_FDS 256
static Bool tainted_fds[VG_N_THREADS][MAXIMUM_FDS];


void FL_(setup_tainted_map)( void ) {
  ThreadId t = 0;
  VG_(memset)(tainted_fds, False, sizeof(tainted_fds));
  /* Taint stdin if specified */
  if (FL_(clo_taint_stdin))
    for(t=0; t < VG_N_THREADS; ++t)
      tainted_fds[t][0] = True;
}


/* Dup of strstr for arbitrary bytes */
static
Char* memmem(Char *haystack, Char *needle, SizeT h_len, SizeT n_len) {
  SizeT count = h_len;
  Char *cursor = haystack;
  if (h_len < n_len)
    return NULL;
  if (haystack == NULL)
     return NULL;
  while (count >= n_len) {
     if (VG_(memcmp)(cursor, needle, n_len) == 0)
        return (Char*)cursor;
     cursor++;
     count--;
   }
   return NULL;
}


void FL_(syscall_read)(ThreadId tid, SysRes res) {
  Int fd = -1;
  Char *data = NULL;
  populate_guest_args(tid);

  fd = guest_args[tid].args[3];
  data = (Char *)(guest_args[tid].args[1]);

  if (fd < 0 || res.res <= 0)
    return;

  // for (;guest_args[tid].used > 0; guest_args[tid].used--)
  //   VG_(printf)("[%d]syscall_read: arg%d: %lx\n", tid, guest_args[tid].used, guest_args[tid].args[guest_args[tid].used]);

   // VG_(printf)("[%d]syscall_read: fd:%d p:%p res:%ul\n", tid, fd, data, res.res);

  if (fd < MAXIMUM_FDS && tainted_fds[tid][fd] == True) {
      FL_(make_mem_undefined)((UWord)data, res.res);
      return;
  }

  /* --taint-file __OR__ taint-string
   * XXX: add better arguments
   */
  if (FL_(clo_taint_string) != NULL) {
    SizeT remaining = res.res;
    SizeT taint_len = VG_(strlen)(FL_(clo_taint_string));
    while (data != NULL && remaining > taint_len) {
      /* XXX: this is tricky - should tainting above still be done? */
      if (!VG_(am_is_valid_for_client)((UWord)data, remaining, VKI_PROT_NONE)) {
        return;
      }

      data = memmem(data, FL_(clo_taint_string), remaining, taint_len);
      if (data != NULL) {
        remaining = res.res - (data - ((Char *)guest_args[tid].args[1]));
        FL_(make_mem_undefined)((UWord)data, taint_len);
        data += taint_len;
      }
    }
  }
}

void FL_(syscall_close)(ThreadId tid, SysRes res) {
  Int fd = -1;
  populate_guest_args(tid);
  fd = guest_args[tid].args[1];
  if (fd > -1 && fd < MAXIMUM_FDS)
    tainted_fds[tid][fd] = False;
}

void FL_(syscall_open)(ThreadId tid, SysRes res) {
  Char fdpath[MAX_PATH];
  Int fd = res.res;

  // Nothing to do if no file tainting
  // But, if stdin tainting, always taint fd 0...
  if (!FL_(clo_taint_file) && (fd != 0 || !FL_(clo_taint_stdin)))
    return;

  // Get arguments to syscall
  populate_guest_args(tid);

  if (fd > -1 && fd < MAXIMUM_FDS) {
    resolve_fd(fd, fdpath, MAX_PATH-1);
    if ( VG_(strncmp)(fdpath, FL_(clo_file_filter), VG_(strlen)( FL_(clo_file_filter))) != 0 ) {
      tainted_fds[tid][res.res] = False;
    } else {
      tainted_fds[tid][res.res] = True;
    }
  }
  //for (;guest_args[tid].used > 0; guest_args[tid].used--)
  //  VG_(printf)("syscall_open: arg%d: %lx\n", guest_args[tid].used, guest_args[tid].args[guest_args[tid].used]);
}

/* XXX: Rearchitect to be take code from coregrind/m_syswrap
 *      or see if a hook-patch would get accepted to augment syswrap-generic.c
 *      to register a callback like syswrap_pre(void *(func)(const char *const
 *      name)) and post. The name could be an enum as well. This would allow
 *      for platform generic hooking without reimplementing it all.
 *
 * XXX: This is x86 ONLY right now.
 */
#define SC_ARG0  ((UWord *)guest_args[tid].args[1])[0]
#define SC_ARG1  ((UWord *)guest_args[tid].args[1])[1]
#define SC_ARG2  ((UWord *)guest_args[tid].args[1])[2]
#define SC_ARG3  ((UWord *)guest_args[tid].args[1])[3]
#define SC_ARG4  ((UWord *)guest_args[tid].args[1])[4]
#define SC_ARG5  ((UWord *)guest_args[tid].args[1])[5]
void FL_(syscall_socketcall)(ThreadId tid, SysRes res) {
  // Get arguments to the syscall
  populate_guest_args(tid);

  switch (guest_args[tid].args[3]) {
    case VKI_SYS_SOCKET:
      //VG_(printf)("syscall_socketcall: SOCKET\n");
      FL_(syscall_socket)(tid, res);
      break;
    case VKI_SYS_LISTEN:
      //FL_(syscall_listen)(tid, res);
      break;
    case VKI_SYS_ACCEPT:
      //VG_(printf)("syscall_socketcall: ACCEPT\n");
      FL_(syscall_accept)(tid, res);
      break;
    case VKI_SYS_CONNECT:
      //VG_(printf)("syscall_socketcall: CONNECT\n");
      // TODO: submit a syscall hooking patch to valgrind to avoid this.
      FL_(syscall_connect)(tid, res);
      //VG_(printf)("syscall_socketcall: %d\n", *((Int *)guest_args[tid].args[1]));
      //VG_(printf)("syscall_socketcall: %d\n", *((Int *)guest_args[tid].args[2]));
      break;
    case VKI_SYS_GETPEERNAME:
      //VG_(printf)("syscall_socketcall: GETPEERNAME\n");
      break;
    case VKI_SYS_GETSOCKNAME:
      //VG_(printf)("syscall_socketcall: GETSOCKNAME\n");
      break;
    case VKI_SYS_SOCKETPAIR:
      //VG_(printf)("syscall_socketcall: SOCKETPAIR\n");
      FL_(syscall_socketpair)(tid, res);
      break;
    case VKI_SYS_RECV:
     // VG_(printf)("syscall_socketcall: RECV\n");
      break;
    case VKI_SYS_RECVMSG:
      //VG_(printf)("syscall_socketcall: RECVMSG\n");
      FL_(syscall_recvmsg)(tid, res);
      break;
    case VKI_SYS_RECVFROM:
      //VG_(printf)("syscall_socketcall: RECVFROM\n");
      FL_(syscall_recvfrom)(tid, res);
      break;
    case VKI_SYS_SHUTDOWN:
     // VG_(printf)("syscall_socketcall: SHUTDOWN\n");
      break;
    default:
      return;
  }
#if 0
  for (;guest_args[tid].used > 0; guest_args[tid].used--)
    VG_(printf)("syscall_socketcall: arg%d: %lx\n", guest_args[tid].used, guest_args[tid].args[guest_args[tid].used]);
  VG_(printf)("syscall_socketcall: %d\n", res.res);
#endif
}

void FL_(syscall_socket)(ThreadId tid, SysRes res) {
  Int fd = res.res;
  // Nothing to do if no network tainting
  if (!FL_(clo_taint_network))
    return;

  if (fd > -1 && fd < MAXIMUM_FDS) {
    tainted_fds[tid][fd] = True;
    //VG_(printf)("syscall_socket: tainting %d\n", fd);
  }
}



void FL_(syscall_connect)(ThreadId tid, SysRes res) {
  // Assume this is called directly after arguments have been populated.
  Int fd = SC_ARG0;

  // Nothing to do if no network tainting
  if (!FL_(clo_taint_network))
    return;
  if (fd > -1 && fd < MAXIMUM_FDS) {
    tainted_fds[tid][fd] = True;
    // VG_(printf)("syscall_connect: tainting %d\n", fd);
  }
}

void FL_(syscall_socketpair)(ThreadId tid, SysRes res) {
  // Assume this is called directly after arguments have been populated.
  Int fd = ((Int *)SC_ARG3)[0];

  // Nothing to do if no network tainting
  if (!FL_(clo_taint_network))
    return;
  if (fd > -1 && fd < MAXIMUM_FDS) {
    tainted_fds[tid][fd] = True;
    // VG_(printf)("syscall_socketpair: tainting fd %d\n", fd);
  }
}




void FL_(syscall_accept)(ThreadId tid, SysRes res) {
  Int fd = res.res;
  // Nothing to do if no network tainting
  if (!FL_(clo_taint_network))
    return;
  if (fd > -1 && fd < MAXIMUM_FDS) {
    tainted_fds[tid][fd] = True;
    // VG_(printf)("syscall_connect: tainting %d\n", fd);
  }
}

void FL_(syscall_recvfrom)(ThreadId tid, SysRes res) {
  Int fd = SC_ARG0;


  if (fd > -1 && fd < MAXIMUM_FDS && tainted_fds[tid][fd] == True && res.res > 0) {
    FL_(make_mem_undefined)(SC_ARG1, res.res);
  }
}


/* Annoyingly uses the struct msghdr from sys/socket.h
 * XXX: scatter gather array and readv() not yet supported.d 
 */
void FL_(syscall_recvmsg)(ThreadId tid, SysRes res) {
  Int fd = SC_ARG0;
  struct vki_msghdr *msg = (struct vki_msghdr *)SC_ARG1;

  if (fd > -1 && fd < MAXIMUM_FDS && tainted_fds[tid][fd] == True && res.res > 0) {
    // XXX: if MSG_TRUNC, this will taint more memory than it should.
    FL_(make_mem_undefined)((UWord)msg->msg_control, res.res);
  }
}






/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
