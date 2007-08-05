include $(top_srcdir)/Makefile.tool.am

noinst_PROGRAMS = 
if VGP_X86_LINUX
noinst_PROGRAMS += flayer-x86-linux vgpreload_flayer-x86-linux.so
endif
if VGP_AMD64_LINUX
noinst_PROGRAMS += flayer-amd64-linux vgpreload_flayer-amd64-linux.so
endif
if VGP_PPC32_LINUX
noinst_PROGRAMS += flayer-ppc32-linux vgpreload_flayer-ppc32-linux.so
endif
if VGP_PPC64_LINUX
noinst_PROGRAMS += flayer-ppc64-linux vgpreload_flayer-ppc64-linux.so
endif
if VGP_PPC32_AIX5
noinst_PROGRAMS += flayer-ppc32-aix5 vgpreload_flayer-ppc32-aix5.so
endif
if VGP_PPC64_AIX5
noinst_PROGRAMS += flayer-ppc64-aix5 vgpreload_flayer-ppc64-aix5.so
endif

VGPRELOAD_MEMTRACK_SOURCES_COMMON = fl_replace_strmem.c

vgpreload_flayer_x86_linux_so_SOURCES      = $(VGPRELOAD_MEMTRACK_SOURCES_COMMON)
vgpreload_flayer_x86_linux_so_CPPFLAGS     = $(AM_CPPFLAGS_X86_LINUX)
vgpreload_flayer_x86_linux_so_CFLAGS       = $(AM_CFLAGS_X86_LINUX) $(AM_CFLAGS_PIC) -O2
vgpreload_flayer_x86_linux_so_CCASFLAGS    = $(AM_CCASFLAGS_X86_LINUX)
vgpreload_flayer_x86_linux_so_DEPENDENCIES = $(LIBREPLACEMALLOC_X86_LINUX)
vgpreload_flayer_x86_linux_so_LDFLAGS      = \
	$(PRELOAD_LDFLAGS_X86_LINUX) \
	$(LIBREPLACEMALLOC_LDFLAGS_X86_LINUX)

vgpreload_flayer_amd64_linux_so_SOURCES      = $(VGPRELOAD_MEMTRACK_SOURCES_COMMON)
vgpreload_flayer_amd64_linux_so_CPPFLAGS     = $(AM_CPPFLAGS_AMD64_LINUX)
vgpreload_flayer_amd64_linux_so_CFLAGS       = $(AM_CFLAGS_AMD64_LINUX) $(AM_CFLAGS_PIC) -O2
vgpreload_flayer_amd64_linux_so_CCASFLAGS    = $(AM_CCASFLAGS_AMD64_LINUX)
vgpreload_flayer_amd64_linux_so_DEPENDENCIES = $(LIBREPLACEMALLOC_AMD64_LINUX)
vgpreload_flayer_amd64_linux_so_LDFLAGS      = \
	$(PRELOAD_LDFLAGS_AMD64_LINUX) \
	$(LIBREPLACEMALLOC_LDFLAGS_AMD64_LINUX)

vgpreload_flayer_ppc32_linux_so_SOURCES      = $(VGPRELOAD_MEMTRACK_SOURCES_COMMON)
vgpreload_flayer_ppc32_linux_so_CPPFLAGS     = $(AM_CPPFLAGS_PPC32_LINUX)
vgpreload_flayer_ppc32_linux_so_CFLAGS       = $(AM_CFLAGS_PPC32_LINUX) $(AM_CFLAGS_PIC) -O2
vgpreload_flayer_ppc32_linux_so_CCASFLAGS    = $(AM_CCASFLAGS_PPC32_LINUX)
vgpreload_flayer_ppc32_linux_so_DEPENDENCIES = $(LIBREPLACEMALLOC_PPC32_LINUX)
vgpreload_flayer_ppc32_linux_so_LDFLAGS      = \
	$(PRELOAD_LDFLAGS_PPC32_LINUX) \
	$(LIBREPLACEMALLOC_LDFLAGS_PPC32_LINUX)

vgpreload_flayer_ppc64_linux_so_SOURCES      = $(VGPRELOAD_MEMTRACK_SOURCES_COMMON)
vgpreload_flayer_ppc64_linux_so_CPPFLAGS     = $(AM_CPPFLAGS_PPC64_LINUX)
vgpreload_flayer_ppc64_linux_so_CFLAGS       = $(AM_CFLAGS_PPC64_LINUX) $(AM_CFLAGS_PIC) -O2
vgpreload_flayer_ppc64_linux_so_CCASFLAGS    = $(AM_CCASFLAGS_PPC64_LINUX)
vgpreload_flayer_ppc64_linux_so_DEPENDENCIES = $(LIBREPLACEMALLOC_PPC64_LINUX)
vgpreload_flayer_ppc64_linux_so_LDFLAGS      = \
	$(PRELOAD_LDFLAGS_PPC64_LINUX) \
	$(LIBREPLACEMALLOC_LDFLAGS_PPC64_LINUX)

vgpreload_flayer_ppc32_aix5_so_SOURCES      = $(VGPRELOAD_MEMTRACK_SOURCES_COMMON)
vgpreload_flayer_ppc32_aix5_so_CPPFLAGS     = $(AM_CPPFLAGS_PPC32_AIX5)
vgpreload_flayer_ppc32_aix5_so_CFLAGS       = $(AM_CFLAGS_PPC32_AIX5) $(AM_CFLAGS_PIC) -O2
vgpreload_flayer_ppc32_aix5_so_CCASFLAGS    = $(AM_CCASFLAGS_PPC32_AIX5)
vgpreload_flayer_ppc32_aix5_so_DEPENDENCIES = $(LIBREPLACEMALLOC_PPC32_AIX5)
vgpreload_flayer_ppc32_aix5_so_LDFLAGS      = \
	$(PRELOAD_LDFLAGS_PPC32_AIX5) \
	$(LIBREPLACEMALLOC_LDFLAGS_PPC32_AIX5)

vgpreload_flayer_ppc64_aix5_so_SOURCES      = $(VGPRELOAD_MEMTRACK_SOURCES_COMMON)
vgpreload_flayer_ppc64_aix5_so_CPPFLAGS     = $(AM_CPPFLAGS_PPC64_AIX5)
vgpreload_flayer_ppc64_aix5_so_CFLAGS       = $(AM_CFLAGS_PPC64_AIX5) $(AM_CFLAGS_PIC) -O2
vgpreload_flayer_ppc64_aix5_so_CCASFLAGS    = $(AM_CCASFLAGS_PPC64_AIX5)
vgpreload_flayer_ppc64_aix5_so_DEPENDENCIES = $(LIBREPLACEMALLOC_PPC64_AIX5)
vgpreload_flayer_ppc64_aix5_so_LDFLAGS      = \
	$(PRELOAD_LDFLAGS_PPC64_AIX5) \
	$(LIBREPLACEMALLOC_LDFLAGS_PPC64_AIX5)

MEMTRACK_SOURCES_COMMON = \
	fl_syswrap.c \
	fl_malloc_wrappers.c \
	fl_main.c \
	fl_translate.c

flayer_x86_linux_SOURCES      = $(MEMTRACK_SOURCES_COMMON)
flayer_x86_linux_CPPFLAGS     = $(AM_CPPFLAGS_X86_LINUX)
flayer_x86_linux_CFLAGS       = $(AM_CFLAGS_X86_LINUX) -O2
flayer_x86_linux_CCASFLAGS    = $(AM_CCASFLAGS_X86_LINUX)
flayer_x86_linux_DEPENDENCIES = $(COREGRIND_LIBS_X86_LINUX)
flayer_x86_linux_LDADD        = $(TOOL_LDADD_X86_LINUX)
flayer_x86_linux_LDFLAGS      = $(TOOL_LDFLAGS_X86_LINUX)

flayer_amd64_linux_SOURCES      = $(MEMTRACK_SOURCES_COMMON)
flayer_amd64_linux_CPPFLAGS     = $(AM_CPPFLAGS_AMD64_LINUX)
flayer_amd64_linux_CFLAGS       = $(AM_CFLAGS_AMD64_LINUX) -O2
flayer_amd64_linux_CCASFLAGS    = $(AM_CCASFLAGS_AMD64_LINUX)
flayer_amd64_linux_DEPENDENCIES = $(COREGRIND_LIBS_AMD64_LINUX)
flayer_amd64_linux_LDADD        = $(TOOL_LDADD_AMD64_LINUX)
flayer_amd64_linux_LDFLAGS      = $(TOOL_LDFLAGS_AMD64_LINUX)

flayer_ppc32_linux_SOURCES      = $(MEMTRACK_SOURCES_COMMON)
flayer_ppc32_linux_CPPFLAGS     = $(AM_CPPFLAGS_PPC32_LINUX)
flayer_ppc32_linux_CFLAGS       = $(AM_CFLAGS_PPC32_LINUX) -O2
flayer_ppc32_linux_CCASFLAGS    = $(AM_CCASFLAGS_PPC32_LINUX)
flayer_ppc32_linux_DEPENDENCIES = $(COREGRIND_LIBS_PPC32_LINUX)
flayer_ppc32_linux_LDADD        = $(TOOL_LDADD_PPC32_LINUX)
flayer_ppc32_linux_LDFLAGS      = $(TOOL_LDFLAGS_PPC32_LINUX)

flayer_ppc64_linux_SOURCES      = $(MEMTRACK_SOURCES_COMMON)
flayer_ppc64_linux_CPPFLAGS     = $(AM_CPPFLAGS_PPC64_LINUX)
flayer_ppc64_linux_CFLAGS       = $(AM_CFLAGS_PPC64_LINUX) -O2
flayer_ppc64_linux_CCASFLAGS    = $(AM_CCASFLAGS_PPC64_LINUX)
flayer_ppc64_linux_DEPENDENCIES = $(COREGRIND_LIBS_PPC64_LINUX)
flayer_ppc64_linux_LDADD        = $(TOOL_LDADD_PPC64_LINUX)
flayer_ppc64_linux_LDFLAGS      = $(TOOL_LDFLAGS_PPC64_LINUX)

flayer_ppc32_aix5_SOURCES      = $(MEMTRACK_SOURCES_COMMON)
flayer_ppc32_aix5_CPPFLAGS     = $(AM_CPPFLAGS_PPC32_AIX5)
flayer_ppc32_aix5_CFLAGS       = $(AM_CFLAGS_PPC32_AIX5) -O2
flayer_ppc32_aix5_CCASFLAGS    = $(AM_CCASFLAGS_PPC32_AIX5)
flayer_ppc32_aix5_DEPENDENCIES = $(COREGRIND_LIBS_PPC32_AIX5)
flayer_ppc32_aix5_LDADD        = $(TOOL_LDADD_PPC32_AIX5)
flayer_ppc32_aix5_LDFLAGS      = $(TOOL_LDFLAGS_PPC32_AIX5)

flayer_ppc64_aix5_SOURCES      = $(MEMTRACK_SOURCES_COMMON)
flayer_ppc64_aix5_CPPFLAGS     = $(AM_CPPFLAGS_PPC64_AIX5)
flayer_ppc64_aix5_CFLAGS       = $(AM_CFLAGS_PPC64_AIX5) -O2
flayer_ppc64_aix5_CCASFLAGS    = $(AM_CCASFLAGS_PPC64_AIX5)
flayer_ppc64_aix5_DEPENDENCIES = $(COREGRIND_LIBS_PPC64_AIX5)
flayer_ppc64_aix5_LDADD        = $(TOOL_LDADD_PPC64_AIX5)
flayer_ppc64_aix5_LDFLAGS      = $(TOOL_LDFLAGS_PPC64_AIX5)

mcincludedir = $(includedir)/valgrind

mcinclude_HEADERS = \
	flayer.h

noinst_HEADERS =	\
	fl_include.h

fl_syswrap.o: CFLAGS += -fno-omit-frame-pointer

fl_replace_strmem.o: CFLAGS += -fno-omit-frame-pointer

fl_main.o: CFLAGS += -fomit-frame-pointer
