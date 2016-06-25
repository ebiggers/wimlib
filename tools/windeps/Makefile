#
# This Makefile builds the third-party libraries needed to build a standalone
# libwim.dll for Windows.  We build these third-party libraries ourselves mainly
# to cut down on bloat.  They are automatically downloaded from the URLs
# declared below and verified against the checksums given in the 'sha256sums'
# file.
#
# This Makefile requires a GNU toolchain with MinGW-w64 (i686 and x86_64
# versions).
#

ARCHITECTURES		:= i686 x86_64
LIBXML2_VERSION		:= 2.9.4
WINPTHREADS_VERSION	:= 4.0.4

LIBXML_URL		:= ftp://xmlsoft.org/libxml2/libxml2-$(LIBXML2_VERSION).tar.gz
WINPTHREADS_URL		:= http://downloads.sourceforge.net/mingw-w64/mingw-w64/mingw-w64-release/mingw-w64-v$(WINPTHREADS_VERSION).tar.bz2


LIBXML_SRCDIR		:= libxml2-$(LIBXML2_VERSION)
LIBXML_DIST		:= $(LIBXML_SRCDIR).tar.gz
SRCDIR_TARGETS		+= $(LIBXML_SRCDIR)
DIST_TARGETS		+= $(LIBXML_DIST)
$(LIBXML_DIST):
	wget $(LIBXML_URL)
$(LIBXML_SRCDIR):$(LIBXML_DIST) checksums_verified
	tar xvf $<
	cp $@/COPYING COPYING.libxml2
MAKE_CLEAN_FILES += $(LIBXML_SRCDIR) COPYING.libxml2

WINPTHREADS_DIST	:= mingw-w64-v$(WINPTHREADS_VERSION).tar.bz2
WINPTHREADS_SRCDIR	:= winpthreads-$(WINPTHREADS_VERSION)
SRCDIR_TARGETS		+= $(WINPTHREADS_SRCDIR)
DIST_TARGETS		+= $(WINPTHREADS_DIST)
$(WINPTHREADS_DIST):
	wget $(WINPTHREADS_URL)
$(WINPTHREADS_SRCDIR):$(WINPTHREADS_DIST) checksums_verified
	tar xvf $<
	cp -aT mingw-w64-v$(WINPTHREADS_VERSION)/mingw-w64-libraries/winpthreads $@
	cp $@/COPYING COPYING.winpthreads
MAKE_CLEAN_FILES += $(WINPTHREADS_SRCDIR) mingw-w64-v$(WINPTHREADS_VERSION) COPYING.winpthreads

checksums_verified:$(DIST_TARGETS)
	sha256sum -c sha256sums

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
		--with-tree					\
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
# declare_arch_targets(arch)
#
define declare_arch_targets
$(eval $(call declare_libxml_target,$(1)))
$(eval $(call declare_winpthreads_target,$(1)))

sysroot_$(1): $($(1)_BUILD_TARGETS)

ALL_SYSROOTS += sysroot_$(1)
MAKE_CLEAN_FILES += sysroot_$(1)
endef

$(foreach arch,$(ARCHITECTURES),$(eval $(call declare_arch_targets,$(arch))))

all: $(ALL_SYSROOTS)

clean:
	rm -rf $(MAKE_CLEAN_FILES) $(DIST_TARGETS)

.PHONY: all clean $(SRCDIR_TARGETS) checksums_verified

.DEFAULT_GOAL = all
