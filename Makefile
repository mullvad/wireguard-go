PREFIX ?= /usr
DESTDIR ?=
LIBDEST ?= $(CURDIR)
BINDIR ?= $(PREFIX)/bin
TARGET ?=
export GO111MODULE := on

all: generate-version-and-build

MAKEFLAGS += --no-print-directory

generate-version-and-build:
	@export GIT_CEILING_DIRECTORIES="$(realpath $(CURDIR)/..)" && \
	tag="$$(git describe --dirty 2>/dev/null)" && \
	ver="$$(printf 'package main\n\nconst Version = "%s"\n' "$$tag")" && \
	[ "$$(cat version.go 2>/dev/null)" != "$$ver" ] && \
	echo "$$ver" > version.go && \
	git update-index --assume-unchanged version.go || true
	@$(MAKE) wireguard-go

wireguard-go: $(wildcard *.go) $(wildcard */*.go)
	go build -v -o "$@"

install: wireguard-go
	@install -v -d "$(DESTDIR)$(BINDIR)" && install -v -m 0755 "$<" "$(DESTDIR)$(BINDIR)/wireguard-go"

daita: libmaybenot.a
	go build --tags daita -v -o wireguard-go

libmaybenot.a: $(wildcard maybenot/*)
	make --directory maybenot/crates/maybenot-ffi/ DESTINATION=$(LIBDEST) TARGET=$(TARGET)

test:
	go test ./...

clean:
	rm -f wireguard-go
	rm -f libmaybenot.a

.PHONY: all clean test install generate-version-and-build
