
/*--------------------------------------------------------------------*/
/*--- malloc/free wrappers for detecting errors and updating bits. ---*/
/*---                                         fl_malloc_wrappers.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Flayer, a heavyweight Valgrind tool for
   tracking marked/tainted data through memory.

   Copyright (C) 2006,2007 Will Drewry <redpig@dataspill.org>
   Some portions copyright (C) 2007 Google Inc.

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
#include "pub_tool_execontext.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_options.h"
#include "pub_tool_replacemalloc.h"
#include "pub_tool_threadstate.h"
#include "pub_tool_tooliface.h"     // Needed for fl_include.h
#include "pub_tool_stacktrace.h"    // For VG_(get_and_pp_StackTrace)

#include "fl_include.h"

/*------------------------------------------------------------*/
/*--- Defns                                                ---*/
/*------------------------------------------------------------*/

/* Stats ... */
static SizeT cmalloc_n_mallocs  = 0;
static SizeT cmalloc_n_frees    = 0;
static SizeT cmalloc_bs_mallocd = 0;

/* For debug printing to do with mempools: what stack trace
   depth to show. */
#define MEMPOOL_DEBUG_STACKTRACE_DEPTH 16


/*------------------------------------------------------------*/
/*--- Tracking malloc'd and free'd blocks                  ---*/
/*------------------------------------------------------------*/

/* Record malloc'd blocks. */
VgHashTable FL_(malloc_list) = NULL;

/* Memory pools. */
VgHashTable FL_(mempool_list) = NULL;
   
/* Records blocks after freeing. */
static FL_Chunk* freed_list_start  = NULL;
static FL_Chunk* freed_list_end    = NULL;
static Int       freed_list_volume = 0;

/* Put a shadow chunk on the freed blocks queue, possibly freeing up
   some of the oldest blocks in the queue at the same time. */
static void add_to_freed_queue ( FL_Chunk* mc )
{
   /* Put it at the end of the freed list */
   if (freed_list_end == NULL) {
      tl_assert(freed_list_start == NULL);
      freed_list_end    = freed_list_start = mc;
      freed_list_volume = mc->szB;
   } else {
      tl_assert(freed_list_end->next == NULL);
      freed_list_end->next = mc;
      freed_list_end       = mc;
      freed_list_volume += mc->szB;
   }
   mc->next = NULL;

   /* Release enough of the oldest blocks to bring the free queue
      volume below vg_clo_freelist_vol. */

   while (freed_list_volume > FL_(clo_freelist_vol)) {
      FL_Chunk* mc1;

      tl_assert(freed_list_start != NULL);
      tl_assert(freed_list_end != NULL);

      mc1 = freed_list_start;
      freed_list_volume -= mc1->szB;
      /* VG_(printf)("volume now %d\n", freed_list_volume); */
      tl_assert(freed_list_volume >= 0);

      if (freed_list_start == freed_list_end) {
         freed_list_start = freed_list_end = NULL;
      } else {
         freed_list_start = mc1->next;
      }
      mc1->next = NULL; /* just paranoia */

      /* free FL_Chunk */
      VG_(cli_free) ( (void*)(mc1->data) );
      VG_(free) ( mc1 );
   }
}

FL_Chunk* FL_(get_freed_list_head)(void)
{
   return freed_list_start;
}

/* Allocate its shadow chunk, put it on the appropriate list. */
static
FL_Chunk* create_FL_Chunk ( ThreadId tid, Addr p, SizeT szB,
                            FL_AllocKind kind)
{
   FL_Chunk* mc  = VG_(malloc)(sizeof(FL_Chunk));
   mc->data      = p;
   mc->szB       = szB;
   mc->allockind = kind;
   mc->where     = VG_(record_ExeContext)(tid);

   /* Paranoia ... ensure the FL_Chunk is off-limits to the client, so
      the mc->data field isn't visible to the leak checker.  If memory
      management is working correctly, any pointer returned by VG_(malloc)
      should be noaccess as far as the client is concerned. */
   if (!FL_(check_mem_is_noaccess)( (Addr)mc, sizeof(FL_Chunk), NULL )) {
      VG_(tool_panic)("create_FL_Chunk: shadow area is accessible");
   } 
   return mc;
}

/*------------------------------------------------------------*/
/*--- client_malloc(), etc                                 ---*/
/*------------------------------------------------------------*/

static Bool complain_about_silly_args(SizeT sizeB, Char* fn)
{
   // Cast to a signed type to catch any unexpectedly negative args.  We're
   // assuming here that the size asked for is not greater than 2^31 bytes
   // (for 32-bit platforms) or 2^63 bytes (for 64-bit platforms).
   if ((SSizeT)sizeB < 0) {
      VG_(message)(Vg_UserMsg, "Warning: silly arg (%ld) to %s()",
                   (SSizeT)sizeB, fn );
      return True;
   }
   return False;
}

static Bool complain_about_silly_args2(SizeT n, SizeT sizeB)
{
   if ((SSizeT)n < 0 || (SSizeT)sizeB < 0) {
      VG_(message)(Vg_UserMsg, "Warning: silly args (%ld,%ld) to calloc()",
                   (SSizeT)n, (SSizeT)sizeB);
      return True;
   }
   return False;
}

/* Allocate memory and note change in memory available */
__inline__
void* FL_(new_block) ( ThreadId tid,
                        Addr p, SizeT szB, SizeT alignB, UInt rzB,
                        Bool is_zeroed, FL_AllocKind kind, VgHashTable table)
{
   cmalloc_n_mallocs ++;

   // Allocate and zero if necessary
   if (p) {
      tl_assert(FL_AllocCustom == kind);
   } else {
      tl_assert(FL_AllocCustom != kind);
      p = (Addr)VG_(cli_malloc)( alignB, szB );
      if (!p) {
         return NULL;
      }
      if (is_zeroed) VG_(memset)((void*)p, 0, szB);
   }

   // Only update this stat if allocation succeeded.
   cmalloc_bs_mallocd += szB;

   VG_(HT_add_node)( table, create_FL_Chunk(tid, p, szB, kind) );

   FL_(make_mem_defined)( p, szB );

   return (void*)p;
}

void* FL_(malloc) ( ThreadId tid, SizeT n )
{
   if (complain_about_silly_args(n, "malloc")) {
      return NULL;
   } else {
      return FL_(new_block) ( tid, 0, n, VG_(clo_alignment), 
         FL_MALLOC_REDZONE_SZB, /*is_zeroed*/False, FL_AllocMalloc,
         FL_(malloc_list));
   }
}

void* FL_(__builtin_new) ( ThreadId tid, SizeT n )
{
   if (complain_about_silly_args(n, "__builtin_new")) {
      return NULL;
   } else {
      return FL_(new_block) ( tid, 0, n, VG_(clo_alignment), 
         FL_MALLOC_REDZONE_SZB, /*is_zeroed*/False, FL_AllocNew,
         FL_(malloc_list));
   }
}

void* FL_(__builtin_vec_new) ( ThreadId tid, SizeT n )
{
   if (complain_about_silly_args(n, "__builtin_vec_new")) {
      return NULL;
   } else {
      return FL_(new_block) ( tid, 0, n, VG_(clo_alignment), 
         FL_MALLOC_REDZONE_SZB, /*is_zeroed*/False, FL_AllocNewVec,
         FL_(malloc_list));
   }
}

void* FL_(memalign) ( ThreadId tid, SizeT alignB, SizeT n )
{
   if (complain_about_silly_args(n, "memalign")) {
      return NULL;
   } else {
      return FL_(new_block) ( tid, 0, n, alignB, 
         FL_MALLOC_REDZONE_SZB, /*is_zeroed*/False, FL_AllocMalloc,
         FL_(malloc_list));
   }
}

void* FL_(calloc) ( ThreadId tid, SizeT nmemb, SizeT size1 )
{
   if (complain_about_silly_args2(nmemb, size1)) {
      return NULL;
   } else {
      return FL_(new_block) ( tid, 0, nmemb*size1, VG_(clo_alignment),
         FL_MALLOC_REDZONE_SZB, /*is_zeroed*/True, FL_AllocMalloc,
         FL_(malloc_list));
   }
}

static
void die_and_free_mem ( ThreadId tid, FL_Chunk* mc, SizeT rzB )
{
   /* Note: make redzones noaccess again -- just in case user made them
      accessible with a client request... */
   FL_(make_mem_noaccess)( mc->data-rzB, mc->szB + 2*rzB );
   /* Untaint this data */
   FL_(make_mem_defined)( mc->data-rzB, mc->szB + 2*rzB );

   /* Put it out of harm's way for a while, if not from a client request */
   if (FL_AllocCustom != mc->allockind) {
      /* Record where freed */
      mc->where = VG_(record_ExeContext) ( tid );
      add_to_freed_queue ( mc );
   } else {
      VG_(free) ( mc );
   }
}

__inline__
void FL_(handle_free) ( ThreadId tid, Addr p, UInt rzB, FL_AllocKind kind )
{
   FL_Chunk* mc;

   cmalloc_n_frees++;

   mc = VG_(HT_remove) ( FL_(malloc_list), (UWord)p );
   if (mc == NULL) {
      FL_(record_free_error) ( tid, p );
   } else {
      /* check if it is a matching free() / delete / delete [] */
      if (kind != mc->allockind) {
         tl_assert(p == mc->data);
         FL_(record_freemismatch_error) ( tid, mc );
      }
      die_and_free_mem ( tid, mc, rzB );
   }
}

void FL_(free) ( ThreadId tid, void* p )
{
   FL_(handle_free)( 
      tid, (Addr)p, FL_MALLOC_REDZONE_SZB, FL_AllocMalloc );
}

void FL_(__builtin_delete) ( ThreadId tid, void* p )
{
   FL_(handle_free)(
      tid, (Addr)p, FL_MALLOC_REDZONE_SZB, FL_AllocNew);
}

void FL_(__builtin_vec_delete) ( ThreadId tid, void* p )
{
   FL_(handle_free)(
      tid, (Addr)p, FL_MALLOC_REDZONE_SZB, FL_AllocNewVec);
}

void* FL_(realloc) ( ThreadId tid, void* p_old, SizeT new_szB )
{
   FL_Chunk* mc;
   void*     p_new;
   SizeT     old_szB;

   cmalloc_n_frees ++;
   cmalloc_n_mallocs ++;
   cmalloc_bs_mallocd += new_szB;

   if (complain_about_silly_args(new_szB, "realloc")) 
      return NULL;

   /* Remove the old block */
   mc = VG_(HT_remove) ( FL_(malloc_list), (UWord)p_old );
   if (mc == NULL) {
      FL_(record_free_error) ( tid, (Addr)p_old );
      /* We return to the program regardless. */
      return NULL;
   }

   /* check if its a matching free() / delete / delete [] */
   if (FL_AllocMalloc != mc->allockind) {
      /* can not realloc a range that was allocated with new or new [] */
      tl_assert((Addr)p_old == mc->data);
      FL_(record_freemismatch_error) ( tid, mc );
      /* but keep going anyway */
   }

   old_szB = mc->szB;

   if (old_szB == new_szB) {
      /* size unchanged */
      mc->where = VG_(record_ExeContext)(tid);
      p_new = p_old;
      
   } else if (old_szB > new_szB) {
      /* new size is smaller */
      FL_(make_mem_noaccess)( mc->data+new_szB, mc->szB-new_szB );
      mc->szB = new_szB;
      mc->where = VG_(record_ExeContext)(tid);
      p_new = p_old;

   } else {
      /* new size is bigger */
      /* Get new memory */
      Addr a_new = (Addr)VG_(cli_malloc)(VG_(clo_alignment), new_szB);

      if (a_new) {
         /* First half kept and copied, second half new, red zones as normal */
         FL_(make_mem_noaccess)( a_new-FL_MALLOC_REDZONE_SZB, FL_MALLOC_REDZONE_SZB );
         FL_(copy_address_range_state)( (Addr)p_old, a_new, mc->szB );
         FL_(make_mem_defined)( a_new+mc->szB, new_szB-mc->szB );
         FL_(make_mem_noaccess) ( a_new+new_szB, FL_MALLOC_REDZONE_SZB );

         /* Copy from old to new */
         VG_(memcpy)((void*)a_new, p_old, mc->szB);

         /* Free old memory */
         /* Nb: we have to allocate a new FL_Chunk for the new memory rather
            than recycling the old one, so that any erroneous accesses to the
            old memory are reported. */
         die_and_free_mem ( tid, mc, FL_MALLOC_REDZONE_SZB );

         // Allocate a new chunk.
         mc = create_FL_Chunk( tid, a_new, new_szB, FL_AllocMalloc );
      }

      p_new = (void*)a_new;
   }  

   // Now insert the new mc (with a possibly new 'data' field) into
   // malloc_list.  If this realloc() did not increase the memory size, we
   // will have removed and then re-added mc unnecessarily.  But that's ok
   // because shrinking a block with realloc() is (presumably) much rarer
   // than growing it, and this way simplifies the growing case.
   VG_(HT_add_node)( FL_(malloc_list), mc );

   return p_new;
}

/* Memory pool stuff. */

void FL_(create_mempool)(Addr pool, UInt rzB, Bool is_zeroed)
{
   FL_Mempool* mp;

   if (VG_(clo_verbosity) > 2) {
      VG_(message)(Vg_UserMsg, "create_mempool(%p, %d, %d)", 
                               pool, rzB, is_zeroed);
      VG_(get_and_pp_StackTrace)
         (VG_(get_running_tid)(), MEMPOOL_DEBUG_STACKTRACE_DEPTH);
   }

   mp = VG_(HT_lookup)(FL_(mempool_list), (UWord)pool);
   if (mp != NULL) {
     VG_(tool_panic)("FL_(create_mempool): duplicate pool creation");
   }
   
   mp = VG_(malloc)(sizeof(FL_Mempool));
   mp->pool       = pool;
   mp->rzB        = rzB;
   mp->is_zeroed  = is_zeroed;
   mp->chunks     = VG_(HT_construct)( 3001 );  // prime, not so big

   /* Paranoia ... ensure this area is off-limits to the client, so
      the mp->data field isn't visible to the leak checker.  If memory
      management is working correctly, anything pointer returned by
      VG_(malloc) should be noaccess as far as the client is
      concerned. */
   if (!FL_(check_mem_is_noaccess)( (Addr)mp, sizeof(FL_Mempool), NULL )) {
      VG_(tool_panic)("FL_(create_mempool): shadow area is accessible");
   } 

   VG_(HT_add_node)( FL_(mempool_list), mp );
}

void FL_(destroy_mempool)(Addr pool)
{
   FL_Chunk*   mc;
   FL_Mempool* mp;

   if (VG_(clo_verbosity) > 2) {
      VG_(message)(Vg_UserMsg, "destroy_mempool(%p)", pool);
      VG_(get_and_pp_StackTrace)
         (VG_(get_running_tid)(), MEMPOOL_DEBUG_STACKTRACE_DEPTH);
   }

   mp = VG_(HT_remove) ( FL_(mempool_list), (UWord)pool );

   if (mp == NULL) {
      ThreadId tid = VG_(get_running_tid)();
      FL_(record_illegal_mempool_error) ( tid, pool );
      return;
   }

   // Clean up the chunks, one by one
   VG_(HT_ResetIter)(mp->chunks);
   while ( (mc = VG_(HT_Next)(mp->chunks)) ) {
      /* Note: make redzones noaccess again -- just in case user made them
         accessible with a client request... */
      FL_(make_mem_noaccess)(mc->data-mp->rzB, mc->szB + 2*mp->rzB );
   }
   // Destroy the chunk table
   VG_(HT_destruct)(mp->chunks);

   VG_(free)(mp);
}

static Int 
mp_compar(void* n1, void* n2)
{
   FL_Chunk* mc1 = *(FL_Chunk**)n1;
   FL_Chunk* mc2 = *(FL_Chunk**)n2;
   return (mc1->data < mc2->data ? -1 : 1);
}

static void 
check_mempool_sane(FL_Mempool* mp)
{
   UInt n_chunks, i, bad = 0;   
   static UInt tick = 0;

   FL_Chunk **chunks = (FL_Chunk**) VG_(HT_to_array)( mp->chunks, &n_chunks );
   if (!chunks)
      return;

   if (VG_(clo_verbosity) > 1) {
     if (tick++ >= 10000)
       {
	 UInt total_pools = 0, total_chunks = 0;
	 FL_Mempool* mp2;
	 
	 VG_(HT_ResetIter)(FL_(mempool_list));
	 while ( (mp2 = VG_(HT_Next)(FL_(mempool_list))) ) {
	   total_pools++;
	   VG_(HT_ResetIter)(mp2->chunks);
	   while (VG_(HT_Next)(mp2->chunks)) {
	     total_chunks++;
	   }
	 }
	 
	 VG_(message)(Vg_UserMsg, 
                      "Total mempools active: %d pools, %d chunks\n", 
		      total_pools, total_chunks);
	 tick = 0;
       }
   }


   VG_(ssort)((void*)chunks, n_chunks, sizeof(VgHashNode*), mp_compar);
         
   /* Sanity check; assert that the blocks are now in order */
   for (i = 0; i < n_chunks-1; i++) {
      if (chunks[i]->data > chunks[i+1]->data) {
         VG_(message)(Vg_UserMsg, 
                      "Mempool chunk %d / %d is out of order "
                      "wrt. its successor", 
                      i+1, n_chunks);
         bad = 1;
      }
   }
   
   /* Sanity check -- make sure they don't overlap */
   for (i = 0; i < n_chunks-1; i++) {
      if (chunks[i]->data + chunks[i]->szB > chunks[i+1]->data ) {
         VG_(message)(Vg_UserMsg, 
                      "Mempool chunk %d / %d overlaps with its successor", 
                      i+1, n_chunks);
         bad = 1;
      }
   }

   if (bad) {
         VG_(message)(Vg_UserMsg, 
                "Bad mempool (%d chunks), dumping chunks for inspection:",
                      n_chunks);
         for (i = 0; i < n_chunks; ++i) {
            VG_(message)(Vg_UserMsg, 
                         "Mempool chunk %d / %d: %d bytes [%x,%x), allocated:",
                         i+1, 
                         n_chunks, 
                         chunks[i]->szB, 
                         chunks[i]->data, 
                         chunks[i]->data + chunks[i]->szB);

            VG_(pp_ExeContext)(chunks[i]->where);
         }
   }
   VG_(free)(chunks);
}

void FL_(mempool_alloc)(ThreadId tid, Addr pool, Addr addr, SizeT szB)
{
   FL_Mempool* mp;

   if (VG_(clo_verbosity) > 2) {     
      VG_(message)(Vg_UserMsg, "mempool_alloc(%p, %p, %d)", pool, addr, szB);
      VG_(get_and_pp_StackTrace) (tid, MEMPOOL_DEBUG_STACKTRACE_DEPTH);
   }

   mp = VG_(HT_lookup) ( FL_(mempool_list), (UWord)pool );
   if (mp == NULL) {
      FL_(record_illegal_mempool_error) ( tid, pool );
   } else {
      check_mempool_sane(mp);
      FL_(new_block)(tid, addr, szB, /*ignored*/0, mp->rzB, mp->is_zeroed,
                     FL_AllocCustom, mp->chunks);
      check_mempool_sane(mp);
   }
}

void FL_(mempool_free)(Addr pool, Addr addr)
{
   FL_Mempool*  mp;
   FL_Chunk*    mc;
   ThreadId     tid = VG_(get_running_tid)();

   mp = VG_(HT_lookup)(FL_(mempool_list), (UWord)pool);
   if (mp == NULL) {
      FL_(record_illegal_mempool_error)(tid, pool);
      return;
   }

   if (VG_(clo_verbosity) > 2) {
      VG_(message)(Vg_UserMsg, "mempool_free(%p, %p)", pool, addr);
      VG_(get_and_pp_StackTrace) (tid, MEMPOOL_DEBUG_STACKTRACE_DEPTH);
   }

   check_mempool_sane(mp);
   mc = VG_(HT_remove)(mp->chunks, (UWord)addr);
   if (mc == NULL) {
      FL_(record_free_error)(tid, (Addr)addr);
      return;
   }

   if (VG_(clo_verbosity) > 2) {
      VG_(message)(Vg_UserMsg, 
		   "mempool_free(%p, %p) freed chunk of %d bytes", 
		   pool, addr, mc->szB);
   }

   die_and_free_mem ( tid, mc, mp->rzB );
   check_mempool_sane(mp);
}


void FL_(mempool_trim)(Addr pool, Addr addr, SizeT szB)
{
   FL_Mempool*  mp;
   FL_Chunk*    mc;
   ThreadId     tid = VG_(get_running_tid)();
   UInt         n_shadows, i;
   VgHashNode** chunks;

   if (VG_(clo_verbosity) > 2) {
      VG_(message)(Vg_UserMsg, "mempool_trim(%p, %p, %d)", pool, addr, szB);
      VG_(get_and_pp_StackTrace) (tid, MEMPOOL_DEBUG_STACKTRACE_DEPTH);
   }

   mp = VG_(HT_lookup)(FL_(mempool_list), (UWord)pool);
   if (mp == NULL) {
      FL_(record_illegal_mempool_error)(tid, pool);
      return;
   }

   check_mempool_sane(mp);
   chunks = VG_(HT_to_array) ( mp->chunks, &n_shadows );
   if (n_shadows == 0) {
     tl_assert(chunks == NULL);
     return;
   }

   tl_assert(chunks != NULL);
   for (i = 0; i < n_shadows; ++i) {

      Addr lo, hi, min, max;

      mc = (FL_Chunk*) chunks[i];

      lo = mc->data;
      hi = mc->szB == 0 ? mc->data : mc->data + mc->szB - 1;

#define EXTENT_CONTAINS(x) ((addr <= (x)) && ((x) < addr + szB))

      if (EXTENT_CONTAINS(lo) && EXTENT_CONTAINS(hi)) {

         /* The current chunk is entirely within the trim extent: keep
            it. */

         continue;

      } else if ( (! EXTENT_CONTAINS(lo)) &&
                  (! EXTENT_CONTAINS(hi)) ) {

         /* The current chunk is entirely outside the trim extent:
            delete it. */

         if (VG_(HT_remove)(mp->chunks, (UWord)mc->data) == NULL) {
            FL_(record_free_error)(tid, (Addr)mc->data);
            VG_(free)(chunks);
            check_mempool_sane(mp);
            return;
         }
         die_and_free_mem ( tid, mc, mp->rzB );  

      } else {

         /* The current chunk intersects the trim extent: remove,
            trim, and reinsert it. */

         tl_assert(EXTENT_CONTAINS(lo) ||
                   EXTENT_CONTAINS(hi));
         if (VG_(HT_remove)(mp->chunks, (UWord)mc->data) == NULL) {
            FL_(record_free_error)(tid, (Addr)mc->data);
            VG_(free)(chunks);
            check_mempool_sane(mp);
            return;
         }

         if (mc->data < addr) {
           min = mc->data;
           lo = addr;
         } else {
           min = addr;
           lo = mc->data;
         }

         if (mc->data + szB > addr + szB) {
           max = mc->data + szB;
           hi = addr + szB;
         } else {
           max = addr + szB;
           hi = mc->data + szB;
         }

         tl_assert(min <= lo);
         tl_assert(lo < hi);
         tl_assert(hi <= max);

         if (min < lo && !EXTENT_CONTAINS(min)) {
           FL_(make_mem_noaccess)( min, lo - min);
         }

         if (hi < max && !EXTENT_CONTAINS(max)) {
           FL_(make_mem_noaccess)( hi, max - hi );
         }

         mc->data = lo;
         mc->szB = (UInt) (hi - lo);
         VG_(HT_add_node)( mp->chunks, mc );        
      }

#undef EXTENT_CONTAINS
      
   }
   check_mempool_sane(mp);
   VG_(free)(chunks);
}

void FL_(move_mempool)(Addr poolA, Addr poolB)
{
   FL_Mempool* mp;

   if (VG_(clo_verbosity) > 2) {
      VG_(message)(Vg_UserMsg, "move_mempool(%p, %p)", poolA, poolB);
      VG_(get_and_pp_StackTrace)
         (VG_(get_running_tid)(), MEMPOOL_DEBUG_STACKTRACE_DEPTH);
   }

   mp = VG_(HT_remove) ( FL_(mempool_list), (UWord)poolA );

   if (mp == NULL) {
      ThreadId tid = VG_(get_running_tid)();
      FL_(record_illegal_mempool_error) ( tid, poolA );
      return;
   }

   mp->pool = poolB;
   VG_(HT_add_node)( FL_(mempool_list), mp );
}

void FL_(mempool_change)(Addr pool, Addr addrA, Addr addrB, SizeT szB)
{
   FL_Mempool*  mp;
   FL_Chunk*    mc;
   ThreadId     tid = VG_(get_running_tid)();

   if (VG_(clo_verbosity) > 2) {
      VG_(message)(Vg_UserMsg, "mempool_change(%p, %p, %p, %d)", 
                   pool, addrA, addrB, szB);
      VG_(get_and_pp_StackTrace) (tid, MEMPOOL_DEBUG_STACKTRACE_DEPTH);
   }

   mp = VG_(HT_lookup)(FL_(mempool_list), (UWord)pool);
   if (mp == NULL) {
      FL_(record_illegal_mempool_error)(tid, pool);
      return;
   }

   check_mempool_sane(mp);

   mc = VG_(HT_remove)(mp->chunks, (UWord)addrA);
   if (mc == NULL) {
      FL_(record_free_error)(tid, (Addr)addrA);
      return;
   }

   mc->data = addrB;
   mc->szB  = szB;
   VG_(HT_add_node)( mp->chunks, mc );

   check_mempool_sane(mp);
}

Bool FL_(mempool_exists)(Addr pool)
{
   FL_Mempool*  mp;

   mp = VG_(HT_lookup)(FL_(mempool_list), (UWord)pool);
   if (mp == NULL) {
       return False;
   }
   return True;
}


/*------------------------------------------------------------*/
/*--- Statistics printing                                  ---*/
/*------------------------------------------------------------*/

void FL_(print_malloc_stats) ( void )
{
   FL_Chunk* mc;
   SizeT     nblocks = 0;
   SizeT     nbytes  = 0;
   
   if (VG_(clo_verbosity) == 0)
      return;
   if (VG_(clo_xml))
      return;

   /* Count memory still in use. */
   VG_(HT_ResetIter)(FL_(malloc_list));
   while ( (mc = VG_(HT_Next)(FL_(malloc_list))) ) {
      nblocks++;
      nbytes += mc->szB;
   }

   VG_(message)(Vg_UserMsg, 
                "malloc/free: in use at exit: %,lu bytes in %,lu blocks.",
                nbytes, nblocks);
   VG_(message)(Vg_UserMsg, 
                "malloc/free: %,lu allocs, %,lu frees, %,lu bytes allocated.",
                cmalloc_n_mallocs,
                cmalloc_n_frees, cmalloc_bs_mallocd);
   if (VG_(clo_verbosity) > 1)
      VG_(message)(Vg_UserMsg, "");
}

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
