/* mkf.c - an executable runtime patcher for x86/linux
 *         Will Drewry <wad@gmail.com>
 *
 * To compile:
 *   gcc -O9 mkf.c -o mkf
 * To use:
 *   mkf --alter-branch=0x804321:1 --alter-fn=0x8093266:100 target arg1 arg2
 *
 * TODO:
 * - Read ELF header from the target file instead of memory
 * - Support more jump instructions
 *
 *   Copyright (C) 2006-2007 Google Inc. (Will Drewry)
 *
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License as
 *   published by the Free Software Foundation; either version 2 of the
 *   License, or (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *   02111-1307, USA.
 *
 *   The GNU General Public License is contained in the file COPYING.
 */
#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <assert.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <linux/user.h>
#include <linux/elf.h>

static const char version[] = "0.1.1";

typedef enum {ALTER_BRANCH, ALTER_FUNCTION} alter_type;
typedef struct _alter_t {
  alter_type type;
  unsigned int address;
  long value;
} alter_t;
/* Currently, only 2 byte and 6 byte jumps are supported. Later this can
 * be cleaned up and extended as needed.
 */
typedef enum {JUMP_NONE=1, JUMP_SHORT=2, JUMP_LONG=6} jump_type;
static const int long_size = sizeof(long);


void print_version() {
  printf("MKF %s - Will Drewry <wad@gmail.com>\n"
         "Copyright 2007 Google Inc\n"
         "Licensed under the GNU Public License\n",
          version);
  return;
}


void print_help() {
  print_version();
  printf("\n"
         "mkf [arguments] /full/path/to/binary [arguments]\n"
         "\n"
         "MKF is a binary runtime patching utility meant for use with\n"
         "Flayer.\n"
         "\n"
         "Arguments:\n"
         "--alter-branch=address:value[,address:value,...] [-b]\n"
         "  Takes in the hex address and a 32-bit value. When the value\n"
         "  is non-zero, the conditional jump at the given address is forced.\n"
         "  When the value is zero, the conditional jump is disabled.\n"
         "  A list of address:value pairs may be supplied.\n"
         "--alter-fn=address:value[,address:value,...] [-f]\n"
         "  Takes in the hex address and a 32-bit value. The nearest call\n"
         "  instruction will be disabled and the value of EAX will be set to\n"
         "  the given value.  A list of address:value pairs may be supplied.\n"
         "--version [-v]\n"
         "  displays the version information\n"
         "--help [-h]\n"
         "  displays this message\n"
         "\n\n");
  return;
}


/* ptrace_extract_chunk
 *
 * This function handles extracting arbitrary-sized chunks of
 * memory from the target application.
 */
long ptrace_extract_chunk(pid_t child, long addr, void *dst, size_t len) {
    ssize_t i = 0, blocks = len / long_size, remainder = len % long_size;
    long shared = 0, result = 0;

    /* Copy whole blocks */
    for( ; i < blocks; ++i, dst+=long_size) {
      result = ptrace(PTRACE_PEEKDATA, child, addr + (i*long_size), NULL);
      memcpy(dst, &result, sizeof(result));
    }

    /* Copy the remaining data that won't fill a whole long */
    if(remainder != 0) {
        shared = ptrace(PTRACE_PEEKDATA, child,
          addr + (blocks*long_size), NULL);
        memcpy(dst, (void *)&shared, remainder);
    }
    return 0;
}


/* ptrace_inject
 *
 * Pokes the specified data over memory in the target application.  It handles
 * overlapping memory to avoid clobbered data unintentionally.
 */
long ptrace_inject(pid_t child, long addr, void *src, size_t len) {
    ssize_t i, blocks = len / long_size, remainder = len % long_size;
    long ret = 0;
    char *code = NULL, *cursor = (char *) src;

    /* If there will be a remainder, copy the src and pad out to
     * be divisble by sizeof(long) */
    if (remainder != 0) {
      code = malloc(long_size * (blocks+1));
      if (code == NULL) return -1;
      /* Now populate the last block with code from the child */
      ret = ptrace(PTRACE_PEEKDATA, child, addr + (blocks*long_size), NULL);
      memcpy(&code[blocks*long_size], &ret, long_size);

      /* Now copy the source over the new allocation */
      memcpy(code, src, len);

      blocks++;
      cursor = code;
    }

    /* Copy whole blocks */
    ret = 0;
    for(i = 0 ; ret == 0 && i < blocks*long_size; i += long_size) {
      long value = 0;
      memcpy(&value, &cursor[i], long_size);

      //printf("0x%hhx 0x%hhx 0x%hhx 0x%hhx (%lu)\n", 
      //  cursor[i], cursor[i+1], cursor[i+2], cursor[i+3], value);

      ret = ptrace(PTRACE_POKEDATA, child, addr+i, value);
      if (ret == -1) perror("[error:ptrace_inject] ptrace");
    }

    if (code) free(code);
    return ret;
}


/* find_call
 *
 * Takes a range and search range/2 bytes before the given address and after it
 * for the 'call' opcode: 0xE8. If found, it returns the address.  Otherwise it
 * returns 0.
 */
long find_call(pid_t pid, long target, size_t range) {
  unsigned char *instr = calloc(1, range);
  static const unsigned char call = 0xe8;
  size_t count;
  long start = target - (range/2);

  if (instr == NULL)
    return 0;
  if (range == 0) {
    free(instr);
    return target;
  }
  if (start < 0 || start > target) {
    free(instr);
    return 0;
  }

  ptrace_extract_chunk(pid, start, instr, range);
  for (count = 0; count < range; count++) {
    if (instr[count] == call) {
      free(instr);
      return start+count;
    }
  }

  free(instr);
  return 0;
}


/* get_jump_type
 *
 * This function checks the opcode at the given address to determine if the
 * total length of the instruction (op+args) is "long" or "short".  It is aware
 * of some of the conditional 2-byte jumps and some of the conditional 6-byte
 * jumps.  If these are found, it will return the jump_type - including
 * JUMP_NONE, if nothing is recognized.
 */
jump_type get_jump_type(pid_t pid, unsigned int address) {
  /* 2 byte near/relative jumps. */
  static const unsigned char shortjmps[] = {
    0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x7c, 0x7d, 0x7e, 0x7f,
  };
  /* 6 byte jumps (e.g. 0x0f80-0x0f8F) */
  unsigned char longjmps[] = {0x0F};
  int op = 0;
  /* Determine if it is a shortjmp or longjmp and modify accordingly */
  long code = ptrace(PTRACE_PEEKTEXT, pid, address, NULL);
  for (;op < sizeof(shortjmps); ++op) {
    if ((code & 0xff) == shortjmps[op])
      return JUMP_SHORT;
  }
  for (op = 0;op < sizeof(longjmps); ++op) {
    if ((code & 0xff) == longjmps[op])
      return JUMP_LONG;
  }
  return JUMP_NONE;
}


/* patch_jump
 *
 * This function enacts conditional jump patching.  It takes a value, and if it
 * is non-zero, it replaces the instruction and, sometimes, its argument with
 * the contents of 'pass' or 'fail'.
 */
bool patch_jump(pid_t pid, unsigned int address, long value,
                const char pass[], size_t pass_len,
                const char fail[], size_t fail_len) {
  if (value) {
    if (ptrace_inject(pid, address, (void *)pass, pass_len) == -1)
      return false;
  } else {
    if (ptrace_inject(pid, address, (void *)fail, fail_len) == -1)
      return false;
  }
  return true;
}

/* patch_short_jump
 *
 * This is a wrapper around patch_jump which specifies the pass/fail
 * instructions needed for overwriting the jump code.
 */
bool patch_short_jump(pid_t pid, unsigned int address, long value) {
  static const unsigned char shortjmp_pass[] = {0xEB};
  static const unsigned char shortjmp_fail[] = {0xEB, 0x00};
  return patch_jump(pid, address, value,
                    shortjmp_pass, sizeof(shortjmp_pass),
                    shortjmp_fail, sizeof(shortjmp_fail));
}


/* patch_long_jump
 *
 * This is a wrapper around patch_jump which specifies the pass/fail
 * instructions needed for overwriting the jump code.
 */
bool patch_long_jump(pid_t pid, unsigned int address, long value) {
  /* It seems that _normally_ following in flayer is different
   * than actually following it.
   */
  static const unsigned char longjmp_fail[] = {0x90, 0xe9};
  static const unsigned char longjmp_pass[] = {
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90
  };
  return patch_jump(pid, address, value,
                    longjmp_pass, sizeof(longjmp_pass),
                    longjmp_fail, sizeof(longjmp_fail));
}


/* patch_function
 *
 * Replaces the 'call' instruction with a 'mov eax' instruction in the target
 * application.  The value moved into EAX is specified as an argument.
 */
bool patch_function(pid_t pid, unsigned int address, long value) {
  /* Not a const as the EAX value will be overwritten */
  static unsigned char fn_code[] = {0xB8, 0x00, 0x0, 0x0, 0x0};

  /* Write in new EAX value */
  memcpy(fn_code+1, &value, sizeof(value));

  if (ptrace_inject(pid, address, fn_code, sizeof(fn_code)) == -1)
    return false;

  return true;
}


/* perform_alterations
 *
 * This function just loops through the alteration array applying the requested
 * patching to the target application.
 */
bool perform_alterations(pid_t pid, const alter_t *alterations, size_t count) {
  size_t i;
  unsigned int real_address = 0;

  for (i = 0; i < count; ++i) {
    const alter_t *entry = &alterations[i];
    switch (entry->type) {
      case ALTER_BRANCH:
        switch (get_jump_type(pid, entry->address)) {
          case JUMP_SHORT:
              if (!patch_short_jump(pid, entry->address, entry->value)) {
                fprintf(stderr, "[error] failed to inject code at %x.\n",
                  entry->address);
                continue;
              }
            break;
          case JUMP_LONG:
              if (!patch_long_jump(pid, entry->address, entry->value)) {
                fprintf(stderr, "[error] failed to inject code at %x.\n",
                  entry->address);
                continue;
              }
            break;
          case JUMP_NONE:
          default:
            fprintf(stderr,
                    "[error] no supported jumps found at %x.\n",
                    entry->address);
            continue;
        }
        break;
      case ALTER_FUNCTION:
        /* Search 4 bytes back and 4 bytes forward for the call instruction */
        real_address = find_call(pid, entry->address, 8);
        if (real_address == 0) {
          fprintf(stderr,
                  "[warning] no call instruction found near %x. skipping.\n",
                  entry->address);
          continue;
        }
        if (!patch_function(pid, real_address, entry->value)) {
          fprintf(stderr, "[error] failed to inject code at %x.\n",
            real_address);
          continue;
        }
        break;
      default:
        fprintf(stderr, "[error] corrupted alteration array encountered\n");
        return false;
    }
  }
  return true;
}


/* breakpoint_and_wait
 *
 * This function takes a pid and an address in the target's space and inserts
 * four INT instructions resulting in a SIGTRAP being sent to the tracer on
 * execution.  It will wait for the trap, restore the instructions that were
 * removed, reset the EIP, and continue.
 *
 * This is used ensure that code injection occurs at the entry point of the
 * target when all linked libraries will be loaded.  This will not help if the
 * target loads a shared object later.
 *
 * XXX: consider adding a breakpoint in dl_open to remedy this.
 */
bool breakpoint_and_wait(pid_t pid, Elf32_Addr address) {
  static const long breakpoint_code = 0xCCCCCCCC;
  struct user_regs_struct regs = {0};
  long original = 0, res = 0;
  int status = 0;

  /* Grab the original instructions at address */
  original = ptrace(PTRACE_PEEKTEXT, pid, address, NULL);
  /* Replace them with 4 breakpoint instructions */
  res = ptrace(PTRACE_POKETEXT, pid, address, breakpoint_code);
  if (res == -1) {
    fprintf(stderr, "[error:%s:%d] ptrace: %s\n",
      __func__, __LINE__, strerror(errno));
    return false;
  }
  /* Wait for them to be triggered */
  res = ptrace(PTRACE_CONT, pid, NULL, NULL);
  if (res == -1) {
    fprintf(stderr, "[error:%s:%d] ptrace: %s\n",
      __func__, __LINE__, strerror(errno));
    return false;
  }
  res = waitpid(pid, &status, 0);
  if (res == -1 || !WIFSTOPPED(status)) {
    ptrace(PTRACE_KILL, pid, NULL, NULL);
    return false;
  }
  /* Replace the original code */
  res = ptrace(PTRACE_POKETEXT, pid, address, original);
  if (res == -1) {
    fprintf(stderr, "[error:%s:%d] ptrace: %s\n",
      __func__, __LINE__, strerror(errno));
    return false;
  }
  /* Reset the EIP to execute the restored instructions */
  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
    fprintf(stderr, "[error:%s:%d] ptrace: %s\n",
      __func__, __LINE__, strerror(errno));
    return false;
  }
  regs.eip = address;
  if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
    fprintf(stderr, "[error:%s:%d] ptrace: %s\n",
      __func__, __LINE__, strerror(errno));
    return false;
  }
  return true;
}

/* attach_and_patch
 *
 * This function handles the fork()ing and attaching. In particular,
 * the parent will call execv() on the target while the child will
 * trace to ensure that the behavior of the target is as similar to
 * normal commandline execution as possible.
 */
void attach_and_patch(const char *command, char *const *args,
                      const alter_t *alterations, size_t count,
                      Elf32_Addr entry) {
  pid_t pid, forkret;
  siginfo_t signal = {0};
  int res = 0, status = 0;

  pid = getpid(); /* Find myself */
  forkret = fork();
  if (forkret < 0)
    return;

  /* Parent: we want this one to exec - not the child. */
  if (forkret != 0) {
    usleep(5000); /* hack yield */
    execv(command, args);
    fprintf(stderr, "[error] execv failed!\n");
    return; /* only reached on execv failure. */
  }

  /* If all goes well, we will not be context swapped and we'll attach
   * _before_ execv() is executed. */
  res = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
  if (res == -1) {
    fprintf(stderr, "[error] failed to trace parent\n");
    fprintf(stderr, "[error:%s:%d] ptrace: %s\n",
      __func__, __LINE__, strerror(errno));
    kill(pid, SIGKILL);
    return;
  }
  res = waitpid(pid, &status, 0);
  if (res == -1 || !WIFSTOPPED(status)) {
    fprintf(stderr, "[error] failed to trace parent\n");
    ptrace(PTRACE_KILL, pid, NULL, NULL);
    return;
  }
  if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &signal) < 0) {
    fprintf(stderr, "[error] failed to acquire signal info\n");
    fprintf(stderr, "[error:%s:%d] ptrace: %s\n",
      __func__, __LINE__, strerror(errno));
    ptrace(PTRACE_KILL, pid, NULL, NULL);
    return;
  }

  /* Wait for SIGTRAP to indicate that we've execv */
  while (signal.si_signo != SIGTRAP) {
    if (signal.si_signo == SIGSTOP) signal.si_signo = 0;
    res = ptrace(PTRACE_CONT, pid, NULL, signal.si_signo);
    if (res == -1) {
      fprintf(stderr, "[error:%s:%d] ptrace: %s\n",
        __func__, __LINE__, strerror(errno));
      ptrace(PTRACE_KILL, pid, NULL, NULL);
      return;
    }
    res = waitpid(pid, &status, 0);
    if (res == -1 || !WIFSTOPPED(status)) {
      fprintf(stderr, "[error] wait returned, but process not stopped\n");
      fprintf(stderr, "[error:%s:%d] ptrace: %s\n",
        __func__, __LINE__, strerror(errno));
      ptrace(PTRACE_KILL, pid, NULL, NULL);
      return;
    }

    if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &signal) < 0) {
      fprintf(stderr, "[error] failed to acquire signal info\n");
      fprintf(stderr, "[error:%s:%d] ptrace: %s\n",
        __func__, __LINE__, strerror(errno));
      ptrace(PTRACE_KILL, pid, NULL, NULL);
      return;
    }
  }

  /* Now that we're in the target, put a breakpoint at the entry address
   * so that we know all the linked libraries are loaded. */
  if (entry == (Elf32_Addr)-1) { 
    Elf32_Ehdr elf;
    fprintf(stderr, "[warning] extracting ELF header from live process\n");
    ptrace_extract_chunk(pid, 0x8048000, &elf, sizeof(elf));
    entry = elf.e_entry;
  }

  if (!breakpoint_and_wait(pid, entry)) {
    fprintf(stderr, "[error] Failed to insert and wait for breakpoint\n");
    ptrace(PTRACE_KILL, pid, NULL, NULL);
    return;
  }

  if (!perform_alterations(pid, alterations, count)) {
    fprintf(stderr, "[error] failed to patch target!\n");
    ptrace(PTRACE_KILL, pid, NULL, NULL);
    return;
  }

  ptrace(PTRACE_DETACH, pid, NULL, NULL);
  /* Success */
  exit(0);
}

Elf32_Addr get_entry_point(const char *const path) {
    int fd = open(path, O_RDONLY);
    ssize_t bytes_read = 0;
    Elf32_Ehdr elf;

    if (fd < 0) {
      fprintf(stderr, "[warning] failed to read executable\n");
      return (Elf32_Addr)-1;
    }

    bytes_read = read(fd, &elf, sizeof(elf));
    if (bytes_read < 0 || bytes_read != sizeof(elf)) {
      fprintf(stderr, "[warning] failed to read ELF header\n");
      close(fd);
      return (Elf32_Addr)-1;
    }
    close(fd);
    return elf.e_entry;
}

signed int command_okay(const char *const path) {
  struct stat buf;
  uid_t uid = getuid();
  gid_t gid = getgid();
  int res = stat(path, &buf);

  if (res < 0)
    return -1;

  if (buf.st_mode & S_IXOTH)
    return 0;

  if (buf.st_uid == uid && buf.st_mode & S_IXUSR)
    return 0;

  if (buf.st_gid == gid && buf.st_mode & S_IXGRP)
    return 0;

  return -1;
}

int main(int argc, char **argv) {
  alter_t *alterations = NULL;
  char *branches = NULL, *functions = NULL, *endptr = NULL;
  size_t branch_count = 0, function_count = 0, cnt = 0;
  char *command = NULL, *const*args = NULL;
  int optindex = 0;
  Elf32_Addr entry = -1;
  struct option longopts[] = {
    {"alter-branch", 1, NULL, 'b'}, /* alter conditional jumps */
    {"alter-fn", 1, NULL, 'f'}, /* alter calls */
    {"wait-for-ld", 1, NULL, 'w'}, /* single step until entry */
    {"help", 0, NULL, 'h'}, /* print help */
    {"version", 0, NULL, 'v'}, /* print version */
    {NULL, 0, NULL, 0}
  };

  /* Extract relevant arguments */
  while (true) {
    bool end = false;
    switch(getopt_long(argc, argv, "+:vhb:f:", longopts, &optindex)) {
      case 'h':
        print_help();
        return 0;
      case 'v':
        print_version();
        return 0;
      case 'b':
        /* Format should be long16:long10,.. */
        endptr = optarg;
        while (true) {
          endptr = strchr(endptr, ',');
          branch_count++;
          if (!endptr++) break;
        }
        branches = optarg;
        break;
      case 'f':
        /* Format should be long16:long10,.. */
        endptr = optarg;
        while (true) {
          endptr = strchr(endptr, ',');
          function_count++;
          if (!endptr++) break;
        }
        functions = optarg;
        break;
      case -1:
        end = true;
        break;
      default:
        fprintf(stderr, "[error] could not parse arguments\n");
        print_help();
        return 1;

    }
    if (end) break;
  }

  if (branch_count > UINT_MAX/2 || function_count > UINT_MAX/2 ||
      branch_count+function_count > UINT_MAX/sizeof(alter_t)) {
    fprintf(stderr, "error: too many functions/branches were specified\n");
    return 1;
  }

  /* Allocate alterations. An array should be fine given the small # of
   * alterations normally required. */
  alterations = (alter_t *)malloc(sizeof(alter_t[branch_count+function_count]));
  if (!alterations) {
    fprintf(stderr, "error: failed to allocate memory for alteration array\n");
    return 1;
  }

  /* Extract branches */
  endptr = branches;
  while(cnt < branch_count) {
    alterations[cnt].type = ALTER_BRANCH;
    if (!isxdigit(*endptr)) {
      fprintf(stderr, "[error] invalid branch format\n");
      print_help();
      return 1;
    }
    alterations[cnt].address = strtol(endptr, &endptr, 16);
    if (endptr == NULL) {
      fprintf(stderr, "[error] invalid branch format\n");
      print_help();
      return 1;
    }
    alterations[cnt++].value = strtol(endptr+1, &endptr, 10);
    if (!endptr++) break;
  }

  /* Extract functions */
  endptr = functions;
  while(cnt < branch_count+function_count) {
    alterations[cnt].type = ALTER_FUNCTION;
    if (!isxdigit(*endptr)) {
      fprintf(stderr, "[error] invalid function format\n");
      print_help();
      return 1;
    }
    alterations[cnt].address = strtol(endptr, &endptr, 16);
    if (endptr == NULL) {
      fprintf(stderr, "[error] invalid function format\n");
      print_help();
      return 1;
    }
    alterations[cnt++].value = strtol(endptr+1, &endptr, 10);
    if (!endptr++) break;
  }

  /* Pull path to the target and arguments from after the -- */
  if (!optind || optind >= argc) {
    fprintf(stderr, "[error] the path to an executable must be specified\n");
    print_help();
    return 1;
  }
  command = argv[optind];
  args = &argv[optind];

  /* check for existence */
  if (command_okay(command) < 0) {
    fprintf(stderr,
      "[error] the full path to a valid executable must be specified\n");
    return 1;
  }

  /* get the entry point from the ELF header */
  entry = get_entry_point(command);

  attach_and_patch(command, args, alterations, branch_count+function_count,
    entry);

  return -1;
}

