# egressguard: build, check and install. The Homebrew formula runs `make install PREFIX=…`.
PREFIX  ?= /usr/local
VERSION := 0.2.1
GO      ?= go
SWIFTC  ?= swiftc
BIN     := build/egressguard
APP     := build/EgressGuard.app
SOURCES := go.mod $(shell find cmd internal -name '*.go' -not -name '*_test.go')

export GOTOOLCHAIN ?= local
export CGO_ENABLED := 1

.PHONY: all test lint install clean

all: $(BIN) $(APP)

$(BIN): $(SOURCES) Makefile # the version is set here
	$(GO) build -trimpath -ldflags "-s -w -X github.com/sentiens/egressguard/internal/guard.Release=$(VERSION)" \
		-o $@ ./cmd/egressguard

$(APP): app/EgressGuardMenu.swift app/Info.plist
	rm -rf "$(APP)"
	mkdir -p "$(APP)/Contents/MacOS"
	$(SWIFTC) -O -swift-version 5 -o "$(APP)/Contents/MacOS/EgressGuard" app/EgressGuardMenu.swift
	cp app/Info.plist "$(APP)/Contents/Info.plist"
	codesign --force --sign - "$(APP)"

test: lint
	$(GO) test -race -count=1 ./...

lint:
	test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }
	$(GO) vet ./...
	bash -n scripts/setup.sh
	bash -n scripts/uninstall.sh
	if command -v shellcheck >/dev/null; then shellcheck scripts/*.sh; fi

# setup.sh and uninstall.sh are only staged here: `sudo egressguard setup` copies the
# binary into a root-owned directory, because launchd must never run code from a
# prefix its user can write to.
install: all
	install -d "$(PREFIX)/bin" "$(PREFIX)/libexec" "$(PREFIX)/share/egressguard"
	install -m 0755 "$(BIN)" "$(PREFIX)/bin/egressguard"
	install -m 0755 scripts/setup.sh scripts/uninstall.sh "$(PREFIX)/libexec/"
	install -m 0644 config/config.json config/config.example.json "$(PREFIX)/share/egressguard/"
	rm -rf "$(PREFIX)/EgressGuard.app"
	cp -R "$(APP)" "$(PREFIX)/EgressGuard.app"

clean:
	rm -rf build
