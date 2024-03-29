EXTENSION    = pg_shared_plans
EXTVERSION   = $(shell grep default_version $(EXTENSION).control | sed -e "s/default_version[[:space:]]*=[[:space:]]*'\([^']*\)'/\1/")
REGRESS      = 00_setup 01_general 02_advanced 03_errors 10_index 20_partition

REGRESS_OPTS = --inputdir=test

PG_CONFIG ?= pg_config

MODULE_big = pg_shared_plans

OBJS = pg_shared_plans.o pgsp_import.o pgsp_inherit.o pgsp_rdepend.o \
	pgsp_utility.o

all:

release-zip: all
	git archive --format zip --prefix=pg_shared_plans-${EXTVERSION}/ --output ./pg_shared_plans-${EXTVERSION}.zip HEAD
	unzip ./pg_shared_plans-$(EXTVERSION).zip
	rm ./pg_shared_plans-$(EXTVERSION).zip
	rm ./pg_shared_plans-$(EXTVERSION)/.gitignore
	rm ./pg_shared_plans-$(EXTVERSION)/docs/ -rf
	rm ./pg_shared_plans-$(EXTVERSION)/typedefs.list
	rm ./pg_shared_plans-$(EXTVERSION)/TODO.md
	sed -i -e "s/__VERSION__/$(EXTVERSION)/g"  ./pg_shared_plans-$(EXTVERSION)/META.json
	zip -r ./pg_shared_plans-$(EXTVERSION).zip ./pg_shared_plans-$(EXTVERSION)/
	rm ./pg_shared_plans-$(EXTVERSION) -rf


DATA = $(wildcard *--*.sql)
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

ifneq ($(MAJORVERSION),$(filter $(MAJORVERSION), 12 13))
	REGRESS += 21_pg14_partition
endif

REGRESS += 30_inheritance

ifneq ($(MAJORVERSION),$(filter $(MAJORVERSION), 12))
	REGRESS += 40_pg13_withties
endif

ifneq ($(MAJORVERSION),$(filter $(MAJORVERSION), 12 13))
	REGRESS += 41_pg14_groupdistinct
endif

REGRESS += 99_cleanup

DEBUILD_ROOT = /tmp/$(EXTENSION)

deb: release-zip
	mkdir -p $(DEBUILD_ROOT) && rm -rf $(DEBUILD_ROOT)/*
	unzip ./${EXTENSION}-$(EXTVERSION).zip -d $(DEBUILD_ROOT)
	cd $(DEBUILD_ROOT)/${EXTENSION}-$(EXTVERSION) && make -f debian/rules orig
	cd $(DEBUILD_ROOT)/${EXTENSION}-$(EXTVERSION) && debuild -us -uc -sa
