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

LIBXML2_VERSION		:= 2.10.3
LIBXML_URL		:= https://download.gnome.org/sources/libxml2/2.10/libxml2-$(LIBXML2_VERSION).tar.xz
LIBXML_SRCDIR		:= libxml2-$(LIBXML2_VERSION)
LIBXML_DIST		:= $(LIBXML_SRCDIR).tar.xz
SRCDIR_TARGETS		+= $(LIBXML_SRCDIR)
DIST_TARGETS		+= $(LIBXML_DIST)
$(LIBXML_DIST):
	wget $(LIBXML_URL)
$(LIBXML_SRCDIR):$(LIBXML_DIST) checksums_verified
	tar xvf $<
	cp $@/Copyright COPYING.libxml2
MAKE_CLEAN_FILES += $(LIBXML_SRCDIR) COPYING.libxml2

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
# declare_arch_targets(arch)
#
define declare_arch_targets
$(eval $(call declare_libxml_target,$(1)))

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
