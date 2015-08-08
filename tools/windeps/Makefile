#
# This Makefile builds the third-party libraries needed to build a standalone
# libwim.dll for Windows.  We build these third-party libraries ourselves mainly
# to cut down on bloat.
#
# Among other things, this Makefile requires MinGW-w64 (i686 and x86_64
# versions) and a windeps.wim containing the following images:
#
# 	- libxml2-2.9.2	[contents of ftp://xmlsoft.org/libxml2/libxml2-2.9.2.tar.gz]
# 	- winpthreads-4.0.4 [directory mingw-w64-libraries/winpthreads from http://downloads.sourceforge.net/mingw-w64/mingw-w64/mingw-w64-release/mingw-w64-v4.0.4.tar.bz2]
# 	- win-iconv-0.0.6 [contents of https://win-iconv.googlecode.com/files/win-iconv-0.0.6.tar.bz2]

ARCHITECTURES		:= i686 x86_64
LIBXML_VERSION		:= 2-2.9.2
WINPTHREADS_VERSION	:= -4.0.4
WINICONV_VERSION	:= -0.0.6

LIBXML_SRCDIR		:= libxml$(LIBXML_VERSION)
SOURCE_TARGETS		+= $(LIBXML_SRCDIR)
$(LIBXML_SRCDIR):
	wimapply --unix-data windeps.wim $(LIBXML_SRCDIR) $(LIBXML_SRCDIR)
	cp $(LIBXML_SRCDIR)/COPYING COPYING.libxml2
MAKE_CLEAN_FILES += $(LIBXML_SRCDIR) COPYING.libxml2

WINPTHREADS_SRCDIR	:= winpthreads$(WINPTHREADS_VERSION)
SOURCE_TARGETS		+= $(WINPTHREADS_SRCDIR)
$(WINPTHREADS_SRCDIR):
	wimapply --unix-data windeps.wim $(WINPTHREADS_SRCDIR) $(WINPTHREADS_SRCDIR)
	cp $(WINPTHREADS_SRCDIR)/COPYING COPYING.winpthreads
MAKE_CLEAN_FILES += $(WINPTHREADS_SRCDIR) COPYING.winpthreads

WINICONV_SRCDIR		:= win-iconv$(WINICONV_VERSION)
SOURCE_TARGETS		+= $(WINICONV_SRCDIR)
$(WINICONV_SRCDIR):
	wimapply --unix-data windeps.wim $(WINICONV_SRCDIR) $(WINICONV_SRCDIR)
# win-iconv is public domain, so there's no license file.
MAKE_CLEAN_FILES	+= $(WINICONV_SRCDIR)

#
# declare_libxml_target(arch)
#
define declare_libxml_target
libxml_$(1):$(LIBXML_SRCDIR)
	builddir=build_libxml_$(1);				\
	rm -rf $$$$builddir;					\
	mkdir $$$$builddir;					\
	cd $$$$builddir;					\
	../$(LIBXML_SRCDIR)/configure				\
		--host=$(1)-w64-mingw32				\
		--enable-static					\
		--disable-shared				\
		--prefix=$$$$PWD/../sysroot_$(1)		\
		CFLAGS=-Os					\
		--with-minimum					\
		--without-lzma					\
		--with-writer;					\
	$(MAKE) install;					\
	rm -f ../sysroot_$(1)/lib/libxml2.la;

$(1)_BUILD_TARGETS += libxml_$(1)
MAKE_CLEAN_FILES += build_libxml_$(1)
endef

#
# declare_winpthreads_target(arch)
#
define declare_winpthreads_target
winpthreads_$(1):$(WINPTHREADS_SRCDIR)
	builddir=build_winpthreads_$(1);			\
	rm -rf $$$$builddir;					\
	cp -r $(WINPTHREADS_SRCDIR) $$$$builddir;		\
	cd $$$$builddir;					\
	./configure						\
		--host=$(1)-w64-mingw32				\
		--enable-static					\
		--disable-shared				\
		--prefix=$$$$PWD/../sysroot_$(1)		\
		CFLAGS=-O2;					\
	$(MAKE) install;					\
	sed -i 's/if defined DLL_EXPORT/if 0/' ../sysroot_$(1)/include/pthread.h;

$(1)_BUILD_TARGETS += winpthreads_$(1)
MAKE_CLEAN_FILES += build_winpthreads_$(1)
endef

#
# declare_winiconv_target(arch)
#
define declare_winiconv_target
winiconv_$(1):$(WINICONV_SRCDIR)
	builddir=build_winiconv_$(1);				\
	rm -rf $$$$builddir;					\
	cp -r $(WINICONV_SRCDIR) $$$$builddir;			\
	cd $$$$builddir;					\
	$(MAKE) CC=$(1)-w64-mingw32-gcc				\
		AR=$(1)-w64-mingw32-ar				\
		RANLIB=$(1)-w64-mingw32-ranlib			\
		DLLTOOL=$(1)-w64-mingw32-dlltool		\
		CFLAGS=-O2					\
		prefix=$$$$PWD/../sysroot_$(1)			\
		install;					\
	rm -f ../sysroot_$(1)/lib/libiconv.dll.a;

$(1)_BUILD_TARGETS += winiconv_$(1)
MAKE_CLEAN_FILES += build_winiconv_$(1)
endef

#
# declare_arch_targets(arch)
#
define declare_arch_targets
$(eval $(call declare_libxml_target,$(1)))
$(eval $(call declare_winpthreads_target,$(1)))
$(eval $(call declare_winiconv_target,$(1)))

sysroot_$(1): $($(1)_BUILD_TARGETS)

ALL_SYSROOTS += sysroot_$(1)
MAKE_CLEAN_FILES += sysroot_$(1)
endef

$(foreach arch,$(ARCHITECTURES),$(eval $(call declare_arch_targets,$(arch))))

all: $(ALL_SYSROOTS)

clean:
	rm -rf $(MAKE_CLEAN_FILES)

.PHONY: all clean $(SOURCE_TARGETS)

.DEFAULT_GOAL = all
