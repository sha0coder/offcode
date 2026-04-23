# offcode — cross-compilation Makefile
# Requires: cargo, cross (cargo install cross), Docker

NAME    := offcode
VERSION := $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*= *"\(.*\)"/\1/')
DIST    := dist
BINDIR  ?= /usr/local/bin

# ── native build ──────────────────────────────────────────────────────────────

# Ad-hoc codesign on macOS so ring/rustls pages pass kernel validation
UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
CODESIGN := codesign -s - --force
else
CODESIGN := true
endif

.PHONY: build
build:
	cargo build --release
	$(CODESIGN) target/release/$(NAME)
	@echo "Binary: target/release/$(NAME)"

.PHONY: run
run:
	cargo run

.PHONY: clean
clean:
	cargo clean
	rm -rf $(DIST)

# ── cross-compilation targets ─────────────────────────────────────────────────
# Install cross: cargo install cross
# cross uses Docker to cross-compile without needing the target toolchain

TARGETS := \
	x86_64-unknown-linux-musl \
	aarch64-unknown-linux-musl \
	x86_64-apple-darwin \
	aarch64-apple-darwin

.PHONY: cross-all
cross-all: $(TARGETS)

# Linux x86_64 (static musl — runs on any Linux, no glibc dep)
.PHONY: x86_64-unknown-linux-musl
x86_64-unknown-linux-musl:
	cross build --release --target $@
	$(call copy_binary,$@,linux-x86_64)

# Linux ARM64 (Raspberry Pi 4, AWS Graviton, etc.)
.PHONY: aarch64-unknown-linux-musl
aarch64-unknown-linux-musl:
	cross build --release --target $@
	$(call copy_binary,$@,linux-arm64)

# macOS x86_64 (Intel Mac) — must run on macOS host with Xcode
.PHONY: x86_64-apple-darwin
x86_64-apple-darwin:
	rustup target add $@ 2>/dev/null || true
	cargo build --release --target $@
	codesign -s - --force target/$@/release/$(NAME)
	$(call copy_binary,$@,macos-x86_64)

# macOS ARM64 (Apple Silicon M1/M2/M3/M4) — must run on macOS host
.PHONY: aarch64-apple-darwin
aarch64-apple-darwin:
	rustup target add $@ 2>/dev/null || true
	cargo build --release --target $@
	codesign -s - --force target/$@/release/$(NAME)
	$(call copy_binary,$@,macos-arm64)

# Universal macOS binary (Intel + Apple Silicon)
.PHONY: macos-universal
macos-universal: x86_64-apple-darwin aarch64-apple-darwin
	mkdir -p $(DIST)
	lipo -create \
		target/x86_64-apple-darwin/release/$(NAME) \
		target/aarch64-apple-darwin/release/$(NAME) \
		-output $(DIST)/$(NAME)-$(VERSION)-macos-universal
	@echo "Universal binary: $(DIST)/$(NAME)-$(VERSION)-macos-universal"

# ── helpers ───────────────────────────────────────────────────────────────────

define copy_binary
	mkdir -p $(DIST)
	cp target/$(1)/release/$(NAME) $(DIST)/$(NAME)-$(VERSION)-$(2)
	@echo "→ $(DIST)/$(NAME)-$(VERSION)-$(2)"
endef

.PHONY: dist
dist: cross-all macos-universal
	ls -lh $(DIST)/

.PHONY: install
install: build
	cp target/release/$(NAME) $(BINDIR)/$(NAME)
	@echo "Installed $(NAME) to $(BINDIR)/$(NAME)"

.PHONY: symstall
symstall: build
	rm -f $(BINDIR)/$(NAME)
	ln -sf $(CURDIR)/target/release/$(NAME) $(BINDIR)/$(NAME)
	@echo "Symlinked $(BINDIR)/$(NAME) -> $(CURDIR)/target/release/$(NAME)"

.PHONY: install-user
install-user: build
	mkdir -p ~/.local/bin
	cp target/release/$(NAME) ~/.local/bin/$(NAME)
	@echo "Installed $(NAME) to ~/.local/bin/$(NAME)"

.PHONY: help
help:
	@echo "offcode build targets:"
	@echo "  make build              Native release build"
	@echo "  make run                Run in dev mode"
	@echo "  make install            Install to \$$(BINDIR) (default /usr/local/bin)"
	@echo "  make symstall           Symlink binary into \$$(BINDIR) (rebuild-friendly)"
	@echo "  make install-user       Install to ~/.local/bin"
	@echo "  make cross-all          Cross-compile all targets (needs cross + Docker)"
	@echo "  make x86_64-unknown-linux-musl   Linux x86_64 static"
	@echo "  make aarch64-unknown-linux-musl  Linux ARM64 static"
	@echo "  make x86_64-apple-darwin         macOS Intel"
	@echo "  make aarch64-apple-darwin        macOS Apple Silicon"
	@echo "  make macos-universal    macOS fat binary (Intel + ARM)"
	@echo "  make dist               Build all + collect to dist/"
	@echo "  make clean              Remove build artifacts"
