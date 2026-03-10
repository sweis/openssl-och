# Build the Rust OCH library and the benchmark driver.
#
# OpenSSL's own Perl-based build system doesn't natively support a Rust
# toolchain step, so this Makefile is self-contained. See build.info and
# NOTES.md for how a tighter integration would be plumbed into `Configure`.

CARGO      ?= cargo
CC         ?= cc
PERL       ?= perl
RUST_DIR    = rust
RUST_LIB    = $(RUST_DIR)/target/release/liboch.a
RUST_SRCS   = $(wildcard $(RUST_DIR)/src/*.rs)
ASM_PL      = asm/areion-x86_64.pl

# Enable AES-NI for the Rust build on x86_64.
RUSTFLAGS  ?= -C target-feature=+aes,+sse2,+ssse3

CFLAGS     ?= -O3 -Wall -Wextra -march=native
LDLIBS      = -lcrypto -lpthread -ldl -lm

.PHONY: all rust test bench valgrind clean

all: rust och_bench asm_test ffi_test

rust: $(RUST_LIB)

# liboch.a bundles the perlasm kernels (build.rs runs the generator itself,
# so it only needs the .pl source to have changed to retrigger).
$(RUST_LIB): $(RUST_SRCS) $(RUST_DIR)/Cargo.toml $(RUST_DIR)/build.rs $(ASM_PL)
	cd $(RUST_DIR) && RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) build --release

och_bench: bench.c och.h $(RUST_LIB)
	$(CC) $(CFLAGS) -o $@ bench.c $(RUST_LIB) $(LDLIBS)

# Standalone ASM-vs-Rust cross-check harness (also used by `make valgrind`).
asm/areion-x86_64.s: $(ASM_PL)
	$(PERL) $(ASM_PL) elf $@

# Both test binaries are built WITHOUT -march=native so valgrind can emulate
# every instruction (AVX-512 from -march=native is not supported by valgrind).
asm_test: asm/asm_test.c asm/areion-x86_64.s $(RUST_LIB)
	$(CC) -g -O2 -Wall -Wextra -o $@ asm/asm_test.c asm/areion-x86_64.s $(RUST_LIB) -lpthread -ldl -lm

# C-FFI correctness/leak harness — walks the full seal/open path.
ffi_test: tests/ffi_test.c och.h $(RUST_LIB)
	$(CC) -g -O2 -Wall -Wextra -o $@ tests/ffi_test.c $(RUST_LIB) -lpthread -ldl -lm

test: $(RUST_LIB) asm_test ffi_test
	cd $(RUST_DIR) && RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) test --release
	cd $(RUST_DIR) && $(CARGO) test
	./asm_test
	./ffi_test

bench: och_bench
	./och_bench

valgrind: asm_test ffi_test
	valgrind --error-exitcode=99 --leak-check=full --show-leak-kinds=all ./asm_test
	valgrind --error-exitcode=99 --leak-check=full --show-leak-kinds=all ./ffi_test

clean:
	cd $(RUST_DIR) && $(CARGO) clean
	rm -f och_bench asm_test ffi_test asm/areion-x86_64.s asm/areion-x86_64.o
