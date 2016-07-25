CARGO_SOURCES := $(shell find src -type f -name '*.rs')
RUSTC ?= rustc
RUST_DIRS := -L target -L target/deps
RUSTC_CMD := $(RUSTC) -D warnings -C rpath $(RUST_DIRS) $(RUST_FLAGS)

librustybones.a: $(CARGO_SOURCE)
	$(RUSTC_CMD) -o $@ --cfg for_c --crate-type staticlib src/lib.rs
