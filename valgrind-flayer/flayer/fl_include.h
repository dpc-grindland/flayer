
/*--------------------------------------------------------------------*/
/*--- A header file for all parts of the Flayer tool.            ---*/
/*---                                                 fl_include.h ---*/
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

#ifndef __FL_INCLUDE_H
#define __FL_INCLUDE_H

#define FL_(str)    VGAPPEND(vgMemCheck_,str)

/*------------------------------------------------------------*/
/*--- Tracking the heap                                    ---*/
/*------------------------------------------------------------*/

/* We want at least a 16B redzone on client heap blocks for Memcheck */
#define FL_MALLOC_REDZONE_SZB    16

/* For malloc()/new/new[] vs. free()/delete/delete[] mismatch checking. */
typedef
   enum {
      FL_AllocMalloc = 0,
      FL_AllocNew    = 1,
      FL_AllocNewVec = 2,
      FL_AllocCustom = 3
   }
   FL_AllocKind;
   
/* Nb: first two fields must match core's VgHashNode. */
typedef
   struct _FL_Chunk {
      struct _FL_Chunk* next;
      Addr         data;            // ptr to actual block
      SizeT        szB : (sizeof(UWord)*8)-2; // size requested; 30 or 62 bits
      FL_AllocKind allockind : 2;   // which wrapper did the allocation
      ExeContext*  where;           // where it was allocated
   }
   FL_Chunk;

/* Memory pool.  Nb: first two fields must match core's VgHashNode. */
typedef
   struct _FL_Mempool {
      struct _FL_Mempool* next;
      Addr          pool;           // pool identifier
      SizeT         rzB;            // pool red-zone size
      Bool          is_zeroed;      // allocations from this pool are zeroed
      VgHashTable   chunks;         // chunks associated with this pool
   }
   FL_Mempool;


extern void* FL_(new_block)  ( ThreadId tid,
                               Addr p, SizeT size, SizeT align, UInt rzB,
                               Bool is_zeroed, FL_AllocKind kind,
                               VgHashTable table);
extern void FL_(handle_free) ( ThreadId tid,
                                Addr p, UInt rzB, FL_AllocKind kind );

extern void FL_(create_mempool)  ( Addr pool, UInt rzB, Bool is_zeroed );
extern void FL_(destroy_mempool) ( Addr pool );
extern void FL_(mempool_alloc)   ( ThreadId tid, Addr pool,
                                   Addr addr, SizeT size );
extern void FL_(mempool_free)    ( Addr pool, Addr addr );
extern void FL_(mempool_trim)    ( Addr pool, Addr addr, SizeT size );
extern void FL_(move_mempool)    ( Addr poolA, Addr poolB );
extern void FL_(mempool_change)  ( Addr pool, Addr addrA, Addr addrB, SizeT size );
extern Bool FL_(mempool_exists)  ( Addr pool );

extern FL_Chunk* FL_(get_freed_list_head)( void );

/* For tracking malloc'd blocks */
extern VgHashTable FL_(malloc_list);

/* For tracking memory pools. */
extern VgHashTable FL_(mempool_list);

/* Shadow memory functions */
extern Bool FL_(check_mem_is_noaccess)( Addr a, SizeT len, Addr* bad_addr );
extern void FL_(make_mem_noaccess) ( Addr a, SizeT len );
extern void FL_(make_mem_undefined)( Addr a, SizeT len );
extern void FL_(make_mem_defined)  ( Addr a, SizeT len );
extern void FL_(copy_address_range_state) ( Addr src, Addr dst, SizeT len );

extern void FL_(print_malloc_stats) ( void );

extern void* FL_(malloc)               ( ThreadId tid, SizeT n );
extern void* FL_(__builtin_new)        ( ThreadId tid, SizeT n );
extern void* FL_(__builtin_vec_new)    ( ThreadId tid, SizeT n );
extern void* FL_(memalign)             ( ThreadId tid, SizeT align, SizeT n );
extern void* FL_(calloc)               ( ThreadId tid, SizeT nmemb, SizeT size1 );
extern void  FL_(free)                 ( ThreadId tid, void* p );
extern void  FL_(__builtin_delete)     ( ThreadId tid, void* p );
extern void  FL_(__builtin_vec_delete) ( ThreadId tid, void* p );
extern void* FL_(realloc)              ( ThreadId tid, void* p, SizeT new_size );

extern void FL_(syscall_open)(ThreadId tid, SysRes res);
extern void FL_(syscall_read)(ThreadId tid, SysRes res);
extern void FL_(syscall_close)(ThreadId tid, SysRes res);
extern void FL_(syscall_socketcall)(ThreadId tid, SysRes res);
extern void FL_(syscall_connect)(ThreadId tid, SysRes res);
extern void FL_(syscall_accept)(ThreadId tid, SysRes res);
extern void FL_(syscall_socket)(ThreadId tid, SysRes res);
extern void FL_(syscall_socketpair)(ThreadId tid, SysRes res);
extern void FL_(syscall_recvfrom)(ThreadId tid, SysRes res);
extern void FL_(syscall_recvmsg)(ThreadId tid, SysRes res);
extern void FL_(setup_tainted_map)( void );
extern void FL_(setup_guest_args)( void );

/*------------------------------------------------------------*/
/*--- Profiling of memory events                           ---*/
/*------------------------------------------------------------*/

/* Define to collect detailed performance info. */
/* #define FL_PROFILE_MEMORY */

#ifdef FL_PROFILE_MEMORY
#  define N_PROF_EVENTS 500

extern UInt   FL_(event_ctr)[N_PROF_EVENTS];
extern HChar* FL_(event_ctr_name)[N_PROF_EVENTS];

#  define PROF_EVENT(ev, name)                                \
   do { tl_assert((ev) >= 0 && (ev) < N_PROF_EVENTS);         \
        /* crude and inaccurate check to ensure the same */   \
        /* event isn't being used with > 1 name */            \
        if (FL_(event_ctr_name)[ev])                         \
           tl_assert(name == FL_(event_ctr_name)[ev]);       \
        FL_(event_ctr)[ev]++;                                \
        FL_(event_ctr_name)[ev] = (name);                    \
   } while (False);

#else

#  define PROF_EVENT(ev, name) /* */

#endif   /* FL_PROFILE_MEMORY */


/*------------------------------------------------------------*/
/*--- V and A bits (Victoria & Albert ?)                   ---*/
/*------------------------------------------------------------*/

/* The number of entries in the primary map can be altered.  However
   we hardwire the assumption that each secondary map covers precisely
   64k of address space. */
#define SM_SIZE 65536            /* DO NOT CHANGE */
#define SM_MASK (SM_SIZE-1)      /* DO NOT CHANGE */

#define V_BIT_UNTAINTED         0
#define V_BIT_TAINTED       1

#define V_BITS8_UNTAINTED       0
#define V_BITS8_TAINTED     0xFF

#define V_BITS16_UNTAINTED      0
#define V_BITS16_TAINTED    0xFFFF

#define V_BITS32_UNTAINTED      0
#define V_BITS32_TAINTED    0xFFFFFFFF

#define V_BITS64_UNTAINTED      0ULL
#define V_BITS64_TAINTED    0xFFFFFFFFFFFFFFFFULL


/*------------------------------------------------------------*/
/*--- Leak checking                                        ---*/
/*------------------------------------------------------------*/

/* A block is either 
   -- Proper-ly reached; a pointer to its start has been found
   -- Interior-ly reached; only an interior pointer to it has been found
   -- Unreached; so far, no pointers to any part of it have been found. 
   -- IndirectLeak; leaked, but referred to by another leaked block
*/
typedef 
   enum { 
      Unreached    =0, 
      IndirectLeak =1,
      Interior     =2, 
      Proper       =3
  }
  Reachedness;

/* For VALGRIND_COUNT_LEAKS client request */
extern SizeT FL_(bytes_leaked);
extern SizeT FL_(bytes_indirect);
extern SizeT FL_(bytes_dubious);
extern SizeT FL_(bytes_reachable);
extern SizeT FL_(bytes_suppressed);

typedef
   enum {
      LC_Off,
      LC_Summary,
      LC_Full,
   }
   LeakCheckMode;

/* A block record, used for generating err msgs. */
typedef
   struct _LossRecord {
      struct _LossRecord* next;
      /* Where these lost blocks were allocated. */
      ExeContext*  allocated_at;
      /* Their reachability. */
      Reachedness  loss_mode;
      /* Number of blocks and total # bytes involved. */
      SizeT        total_bytes;
      SizeT        indirect_bytes;
      UInt         num_blocks;
   }
   LossRecord;

extern void FL_(do_detect_memory_leaks) (
          ThreadId tid, LeakCheckMode mode,
          Bool (*is_within_valid_secondary) ( Addr ),
          Bool (*is_valid_aligned_word)     ( Addr )
       );

extern void FL_(pp_LeakError)(UInt n_this_record, UInt n_total_records,
                              LossRecord* l);
                          

/*------------------------------------------------------------*/
/*--- Errors and suppressions                              ---*/
/*------------------------------------------------------------*/

extern void FL_(record_free_error)            ( ThreadId tid, Addr a ); 
extern void FL_(record_illegal_mempool_error) ( ThreadId tid, Addr a );
extern void FL_(record_freemismatch_error)    ( ThreadId tid, FL_Chunk* mc );
extern Bool FL_(record_leak_error)            ( ThreadId tid,
                                                UInt n_this_record,
                                                UInt n_total_records,
                                                LossRecord* lossRecord,
                                                Bool print_record );

/*------------------------------------------------------------*/
/*--- Command line options + defaults                      ---*/
/*------------------------------------------------------------*/

/* Allow loads from partially-valid addresses?  default: YES */
extern Bool FL_(clo_partial_loads_ok);

/* Max volume of the freed blocks queue. */
extern Int FL_(clo_freelist_vol);

/* Assume accesses immediately below %esp are due to gcc-2.96 bugs.
 * default: NO */
extern Bool FL_(clo_workaround_gcc296_bugs);

/* Alter branch behavior based on a list of instruction address and 1/0 pairs.
 * E.g. --alter-branch=0x804123:0,0x804E423:1,...
 * This will result in the code being instrumented for any Ist_Exit with a
 * matching instruction address.
 */
extern Char* FL_(clo_alter_branch);
extern Char* FL_(clo_alter_fn);
extern Char* FL_(clo_taint_string);
extern Char* FL_(clo_file_filter);
extern Bool FL_(clo_taint_file);
extern Bool FL_(clo_taint_network);
extern Bool FL_(clo_taint_stdin);
extern Bool FL_(clo_verbose_instr);



/*------------------------------------------------------------*/
/*--- Instrumentation                                      ---*/
/*------------------------------------------------------------*/

/* Functions defined in fl_main.c */
extern VG_REGPARM(1) void FL_(helperc_complain_undef) ( HWord );
extern void FL_(helperc_value_check8_fail) ( void );
extern void FL_(helperc_value_check4_fail) ( void );
extern void FL_(helperc_value_check1_fail) ( void );
extern void FL_(helperc_value_check0_fail) ( void );

extern VG_REGPARM(1) void FL_(helperc_STOREV64be) ( Addr, ULong );
extern VG_REGPARM(1) void FL_(helperc_STOREV64le) ( Addr, ULong );
extern VG_REGPARM(2) void FL_(helperc_STOREV32be) ( Addr, UWord );
extern VG_REGPARM(2) void FL_(helperc_STOREV32le) ( Addr, UWord );
extern VG_REGPARM(2) void FL_(helperc_STOREV16be) ( Addr, UWord );
extern VG_REGPARM(2) void FL_(helperc_STOREV16le) ( Addr, UWord );
extern VG_REGPARM(2) void FL_(helperc_STOREV8)   ( Addr, UWord );

extern VG_REGPARM(1) ULong FL_(helperc_LOADV64be) ( Addr );
extern VG_REGPARM(1) ULong FL_(helperc_LOADV64le) ( Addr );
extern VG_REGPARM(1) UWord FL_(helperc_LOADV32be) ( Addr );
extern VG_REGPARM(1) UWord FL_(helperc_LOADV32le) ( Addr );
extern VG_REGPARM(1) UWord FL_(helperc_LOADV16be) ( Addr );
extern VG_REGPARM(1) UWord FL_(helperc_LOADV16le) ( Addr );
extern VG_REGPARM(1) UWord FL_(helperc_LOADV8)    ( Addr );

extern void FL_(helperc_MAKE_STACK_UNINIT) ( Addr base, UWord len );

/* Functions defined in fl_translate.c */
extern
IRSB* FL_(instrument) ( VgCallbackClosure* closure,
                        IRSB* bb_in, 
                        VexGuestLayout* layout, 
                        VexGuestExtents* vge,
                        IRType gWordTy, IRType hWordTy );

#endif /* ndef __FL_INCLUDE_H */

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/

