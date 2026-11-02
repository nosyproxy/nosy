.PHONY: ui build run dev test check fmt clean

CARGO ?= cargo
# Sibling checkout of github.com/nosyproxy/nosy-web; its dist/ is embedded into the binary.
WEB ?= ../nosy-web

## Build the SPA in $(WEB) (embedded via NOSY_UI_DIR, see .cargo/config.toml).
ui:
	@test -d $(WEB) || { echo "nosy-web not found at $(WEB): git clone git@github.com:nosyproxy/nosy-web.git $(WEB)"; exit 1; }
	$(MAKE) -C $(WEB) build

## Optimized single binary with the UI embedded: target/release/nosy
build: ui
	NOSY_UI_DIR=$(abspath $(WEB))/dist $(CARGO) build --release --bin nosy

run: build
	./target/release/nosy --open

## Debug backend; the UI is read from $(WEB)/dist on disk (or use `make dev` in nosy-web for HMR).
dev:
	$(CARGO) run --bin nosy

test:
	$(CARGO) test --workspace

check:
	$(CARGO) fmt --all --check
	$(CARGO) clippy --workspace --all-targets -- -D warnings
	$(CARGO) test --workspace

fmt:
	$(CARGO) fmt --all

clean:
	$(CARGO) clean
