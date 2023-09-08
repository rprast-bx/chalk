BINARY=chalk
CHALK_BUILD?=release
_DOCKER=docker compose run --rm chalk
DOCKER?=$(_DOCKER)

SOURCES=$(wildcard *.nims)
SOURCES+=$(wildcard *.nimble)
SOURCES+=$(shell find src/ -name '*.nim')
SOURCES+=$(shell find src/ -name '*.c4m')
SOURCES+=$(shell find src/ -name '*.c42spec')

VERSION=$(shell cat *.nimble | grep -E "version\s+=" | cut -d'"' -f2)

# not PHONY jobs on purpose but instead rebuilds chalk
# when any of the nim sources change
# (a.k.a what Makefile is good at :D)
$(BINARY): $(SOURCES)
	-rm -f $@
	$(DOCKER) nimble $(CHALK_BUILD)

.PHONY: debug release
debug release:
	-rm -f $(BINARY)
	$(DOCKER) nimble $@

.PHONY: version
version:
	  @echo $(VERSION)

.PHONY: clean
clean:
	-rm -f $(BINARY) src/c4autoconf.nim dist

# ----------------------------------------------------------------------------
# TOOL MAKEFILES

TOOLS=config-tool server

.PHONY: $(TOOLS)
$(TOOLS):
	make -C $@

$(addsuffix /%,$(TOOLS)):
	make -C $(@D) $*

# ----------------------------------------------------------------------------
# TESTS

.PHONY: tests
tests: DOCKER=$(_DOCKER) # force rebuilds to use docker to match tests
tests: $(BINARY) # note this will rebuild chalk if necessary
	docker compose run --rm tests $(make_args) $(args)

.PHONY: parallel
tests_parallel: make_args=-nauto
tests_parallel: tests

# ----------------------------------------------------------------------------
# MISC

.PHONY: sqlite
sqlite: server/sqlite

include .github/Makefile.dist
