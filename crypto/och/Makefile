# Build the Rust OCH library and the benchmark driver.
#
# OpenSSL's own Perl-based build system doesn't natively support a Rust
# toolchain step, so this Makefile is self-contained. See build.info and
# NOTES.md for how a tighter integration would be plumbed into `Configure`.

CARGO      ?= cargo
CC         ?= cc
RUST_DIR    = rust
RUST_LIB    = $(RUST_DIR)/target/release/liboch.a
RUST_SRCS   = $(wildcard $(RUST_DIR)/src/*.rs)

# Enable AES-NI for the Rust build on x86_64.
RUSTFLAGS  ?= -C target-feature=+aes,+sse2,+ssse3

CFLAGS     ?= -O3 -Wall -Wextra -march=native
LDLIBS      = -lcrypto -lpthread -ldl -lm

.PHONY: all rust test bench clean

all: rust och_bench

rust: $(RUST_LIB)

$(RUST_LIB): $(RUST_SRCS) $(RUST_DIR)/Cargo.toml
	cd $(RUST_DIR) && RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) build --release

och_bench: bench.c och.h $(RUST_LIB)
	$(CC) $(CFLAGS) -o $@ bench.c $(RUST_LIB) $(LDLIBS)

test: $(RUST_LIB)
	cd $(RUST_DIR) && RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) test --release
	cd $(RUST_DIR) && $(CARGO) test

bench: och_bench
	./och_bench

clean:
	cd $(RUST_DIR) && $(CARGO) clean
	rm -f och_bench
