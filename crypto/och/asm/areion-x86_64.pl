#! /usr/bin/env perl
# Areion-256 permutation for OCH AEAD — AES-NI optimized x86_64.
#
# Exports:
#   och_asm_areion256_x1     void f(u8 s[32])                           fwd
#   och_asm_areion256_inv_x1 void f(u8 s[32])                           bwd
#   och_asm_areion256_x4     void f(u8 s[4][32])                        fwd ×4
#   och_asm_areion256_inv_x4 void f(u8 s[4][32])                        bwd ×4
#   och_asm_em_enc_x4        void f(u8 blk[4][32], const u8 off[4][32]) EM enc ×4
#   och_asm_em_dec_x4        void f(u8 blk[4][32], const u8 off[4][32]) EM dec ×4
#
# Areion-256 round (forward), 10 rounds, args alternate (x0,x1)⇄(x1,x0):
#     x1 = aesenc(aesenc(x0, RC[i]), x1)
#     x0 = aesenclast(x0, 0)
#
# Inverse round (runs 9→0, same alternation as forward):
#     x0 = aesdeclast(x0, 0)
#     x1 = aesenc(aesenc(x0, RC[i]), x1)        # NB forward aesenc!
#
# Rationale for x4: single-block Areion is latency-bound on the 2-deep
# aesenc chain for x1 (≈8 cyc/round on Skylake-class parts → ~80 cyc/32B,
# i.e. ≈1.8 cpb — matches what the Rust intrinsic path measures). With
# four independent blocks the 12 AES-NI ops/round become throughput-bound:
# ≈12 cyc/round at one aesenc/clock → ~120 cyc/128B ≈ 0.94 cpb.
#
# Licensed under the Apache License 2.0 (matching OpenSSL).

# --------------------------------------------------------------------------
# Prologue — standard OpenSSL Perl-asm plumbing.

$output  = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$win64 = 0; $win64 = 1 if ($flavour =~ /[nm]asm|mingw64/ || ($output && $output =~ /\.asm$/));

$0 =~ m|(.*[\/\\])[^\/\\]+$|; $dir = $1;
( $xlate = "${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate = "${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate ) or
die "can't locate x86_64-xlate.pl";

open OUT, "| \"$^X\" \"$xlate\" $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT = *OUT;

# --------------------------------------------------------------------------
# Round constants (digits of π, first 10 rows for Areion-256).
# Each row packed as four LE u32s — matches `_mm_setr_epi32(r0,r1,r2,r3)`.

my @RC = (
    [0x03707344,0x13198a2e,0x85a308d3,0x243f6a88],
    [0xec4e6c89,0x082efa98,0x299f31d0,0xa4093822],
    [0x34e90c6c,0xbe5466cf,0x38d01377,0x452821e6],
    [0xb5470917,0x3f84d5b5,0xc97c50dd,0xc0ac29b7],
    [0x98dfb5ac,0xd1310ba6,0x8979fb1b,0x9216d5d9],
    [0x6a267e96,0xb8e1afed,0xd01adfb7,0x2ffd72db],
    [0xb3916cf7,0x24a19947,0xf12c7f99,0xba7c9045],
    [0x1574e690,0x36920d87,0x58efc166,0x801f2e28],
    [0x728eb658,0x0d95748f,0xf4933d7e,0xa458fea3],
    [0xc25a59b5,0x7b54a41d,0x82154aee,0x718bcd58],
);

my $code = "";

$code .= ".text\n";
$code .= ".section .rodata\n";
$code .= ".align 64\n";
$code .= ".Larc:\n";
for my $r (@RC) {
    $code .= sprintf "\t.long\t0x%08x,0x%08x,0x%08x,0x%08x\n", @$r;
}
$code .= ".previous\n\n";

# --------------------------------------------------------------------------
# Single-block forward / backward.

# Register assignment (System V AMD64 — Win64 prologue inserted separately):
#   arg0 = %rdi → state pointer
#   x0 = %xmm0, x1 = %xmm1, tmp = %xmm2, zero = %xmm3
#   %r11 → .Larc base (avoids clobbering any callee-saved)

sub round1x_fwd {
    my ($x0,$x1,$i) = @_;
    my $off = 16*$i;
    # tmp = aesenc(x0, RC[i]);  x0 = aesenclast(x0, 0);  x1 = aesenc(tmp, x1)
    return <<___;
	movdqa		$x0, %xmm2
	aesenc		${off}(%r11), %xmm2
	aesenclast	%xmm3, $x0
	aesenc		$x1, %xmm2
	movdqa		%xmm2, $x1
___
}

sub round1x_bwd {
    my ($x0,$x1,$i) = @_;
    my $off = 16*$i;
    # x0 = aesdeclast(x0, 0);  tmp = aesenc(x0, RC[i]);  x1 = aesenc(tmp, x1)
    return <<___;
	aesdeclast	%xmm3, $x0
	movdqa		$x0, %xmm2
	aesenc		${off}(%r11), %xmm2
	aesenc		$x1, %xmm2
	movdqa		%xmm2, $x1
___
}

# ---- forward x1 ----
$code .= <<___;
.globl	och_asm_areion256_x1
.type	och_asm_areion256_x1,\@function,1
.align	16
och_asm_areion256_x1:
.cfi_startproc
___
$code .= "\tendbranch\n" unless $win64;
$code .= <<___;
	lea		.Larc(%rip), %r11
	pxor		%xmm3, %xmm3
	movdqu		(%rdi), %xmm0
	movdqu		16(%rdi), %xmm1
___
for my $i (0..9) {
    my ($x0,$x1) = ($i & 1) ? ("%xmm1","%xmm0") : ("%xmm0","%xmm1");
    $code .= round1x_fwd($x0,$x1,$i);
}
$code .= <<___;
	movdqu		%xmm0, (%rdi)
	movdqu		%xmm1, 16(%rdi)
	ret
.cfi_endproc
.size	och_asm_areion256_x1,.-och_asm_areion256_x1
___

# ---- backward x1 ----
$code .= <<___;
.globl	och_asm_areion256_inv_x1
.type	och_asm_areion256_inv_x1,\@function,1
.align	16
och_asm_areion256_inv_x1:
.cfi_startproc
___
$code .= "\tendbranch\n" unless $win64;
$code .= <<___;
	lea		.Larc(%rip), %r11
	pxor		%xmm3, %xmm3
	movdqu		(%rdi), %xmm0
	movdqu		16(%rdi), %xmm1
___
for my $i (reverse 0..9) {
    # Mirror forward's arg order: round i's (x0,x1) = (xmm1,xmm0) when i odd.
    my ($x0,$x1) = ($i & 1) ? ("%xmm1","%xmm0") : ("%xmm0","%xmm1");
    $code .= round1x_bwd($x0,$x1,$i);
}
$code .= <<___;
	movdqu		%xmm0, (%rdi)
	movdqu		%xmm1, 16(%rdi)
	ret
.cfi_endproc
.size	och_asm_areion256_inv_x1,.-och_asm_areion256_inv_x1
___

# --------------------------------------------------------------------------
# 4-way interleaved core (used by raw perm and by EM kernels).
#
# Register layout (all xmm):
#   a0,a1 = xmm0,xmm1   block A
#   b0,b1 = xmm2,xmm3   block B
#   c0,c1 = xmm4,xmm5   block C
#   d0,d1 = xmm6,xmm7   block D
#   ta,tb,tc,td = xmm8..11   per-block scratch
#   zero = xmm12
#   rc   = xmm13         broadcast RC[i] for this round
#   xmm14 scratch (EM offset load)
#
# r11 → .Larc base.  No callee-saved GPRs touched.

my ($a0,$a1,$b0,$b1,$c0,$c1,$d0,$d1) = map("%xmm$_",0..7);
my ($ta,$tb,$tc,$td) = map("%xmm$_",8..11);
my $z  = "%xmm12";
my $rc = "%xmm13";

sub round4x_fwd {
    my ($p0,$p1,$q0,$q1,$r0,$r1,$s0,$s1,$i) = @_;
    my $off = 16*$i;
    return <<___;
	movdqa		${off}(%r11), $rc
	movdqa		$p0, $ta
	movdqa		$q0, $tb
	movdqa		$r0, $tc
	movdqa		$s0, $td
	aesenc		$rc, $ta
	aesenc		$rc, $tb
	aesenc		$rc, $tc
	aesenc		$rc, $td
	aesenclast	$z,  $p0
	aesenclast	$z,  $q0
	aesenclast	$z,  $r0
	aesenclast	$z,  $s0
	aesenc		$p1, $ta
	aesenc		$q1, $tb
	aesenc		$r1, $tc
	aesenc		$s1, $td
	movdqa		$ta, $p1
	movdqa		$tb, $q1
	movdqa		$tc, $r1
	movdqa		$td, $s1
___
}

sub round4x_bwd {
    my ($p0,$p1,$q0,$q1,$r0,$r1,$s0,$s1,$i) = @_;
    my $off = 16*$i;
    return <<___;
	movdqa		${off}(%r11), $rc
	aesdeclast	$z,  $p0
	aesdeclast	$z,  $q0
	aesdeclast	$z,  $r0
	aesdeclast	$z,  $s0
	movdqa		$p0, $ta
	movdqa		$q0, $tb
	movdqa		$r0, $tc
	movdqa		$s0, $td
	aesenc		$rc, $ta
	aesenc		$rc, $tb
	aesenc		$rc, $tc
	aesenc		$rc, $td
	aesenc		$p1, $ta
	aesenc		$q1, $tb
	aesenc		$r1, $tc
	aesenc		$s1, $td
	movdqa		$ta, $p1
	movdqa		$tb, $q1
	movdqa		$tc, $r1
	movdqa		$td, $s1
___
}

# Given direction, build the full 10-round x4 body.
sub areion256_x4_body {
    my $dir = shift;  # "fwd" or "bwd"
    my $out = "";
    my @rounds = $dir eq "fwd" ? (0..9) : (reverse 0..9);
    for my $i (@rounds) {
        my @args = ($i & 1)
            ? ($a1,$a0,$b1,$b0,$c1,$c0,$d1,$d0,$i)
            : ($a0,$a1,$b0,$b1,$c0,$c1,$d0,$d1,$i);
        $out .= $dir eq "fwd" ? round4x_fwd(@args) : round4x_bwd(@args);
    }
    return $out;
}

# Load 4 states from rdi (contiguous 4×32B).
sub load4x {
    return <<___;
	movdqu		  (%rdi), $a0
	movdqu		16(%rdi), $a1
	movdqu		32(%rdi), $b0
	movdqu		48(%rdi), $b1
	movdqu		64(%rdi), $c0
	movdqu		80(%rdi), $c1
	movdqu		96(%rdi), $d0
	movdqu		112(%rdi), $d1
___
}

sub store4x {
    return <<___;
	movdqu		$a0,   (%rdi)
	movdqu		$a1, 16(%rdi)
	movdqu		$b0, 32(%rdi)
	movdqu		$b1, 48(%rdi)
	movdqu		$c0, 64(%rdi)
	movdqu		$c1, 80(%rdi)
	movdqu		$d0, 96(%rdi)
	movdqu		$d1, 112(%rdi)
___
}

# XOR 4 offsets (from rsi) into the 8 block-lane registers.
sub xor_offsets {
    my $scr = "%xmm14";
    my $out = "";
    my @regs = ($a0,$a1,$b0,$b1,$c0,$c1,$d0,$d1);
    for my $i (0..7) {
        my $off = 16*$i;
        $out .= "\tmovdqu\t\t${off}(%rsi), $scr\n";
        $out .= "\tpxor\t\t$scr, $regs[$i]\n";
    }
    return $out;
}

# Register-clearing helper — zero all scratch xmm to avoid leaking key-like
# material (offsets + permutation state). The Areion temps already overlap
# with block state; clearing the high regs and zero-RC is enough.
sub clear_scratch {
    return <<___;
	pxor		$ta, $ta
	pxor		$tb, $tb
	pxor		$tc, $tc
	pxor		$td, $td
	pxor		$rc, $rc
	pxor		%xmm14, %xmm14
___
}

# ---- och_asm_areion256_x4 / _inv_x4 ----
for my $dir ("fwd","bwd") {
    my $name = $dir eq "fwd" ? "och_asm_areion256_x4"
                             : "och_asm_areion256_inv_x4";
    $code .= <<___;
.globl	$name
.type	$name,\@function,1
.align	32
$name:
.cfi_startproc
___
    $code .= "\tendbranch\n" unless $win64;
    $code .= "\tlea\t\t.Larc(%rip), %r11\n";
    $code .= "\tpxor\t\t$z, $z\n";
    $code .= load4x();
    $code .= areion256_x4_body($dir);
    $code .= store4x();
    $code .= clear_scratch();
    $code .= <<___;
	ret
.cfi_endproc
.size	$name,.-$name
___
}

# ---- och_asm_em_enc_x4 / och_asm_em_dec_x4 ----
# void f(uint8_t blk[4][32], const uint8_t off[4][32])
for my $dir ("fwd","bwd") {
    my $name = $dir eq "fwd" ? "och_asm_em_enc_x4" : "och_asm_em_dec_x4";
    $code .= <<___;
.globl	$name
.type	$name,\@function,2
.align	32
$name:
.cfi_startproc
___
    $code .= "\tendbranch\n" unless $win64;
    $code .= "\tlea\t\t.Larc(%rip), %r11\n";
    $code .= "\tpxor\t\t$z, $z\n";
    $code .= load4x();
    $code .= xor_offsets();
    $code .= areion256_x4_body($dir);
    $code .= xor_offsets();
    $code .= store4x();
    $code .= clear_scratch();
    $code .= <<___;
	ret
.cfi_endproc
.size	$name,.-$name
___
}

# --------------------------------------------------------------------------
# och_asm_em_{enc,dec}_bulk — full bulk loop. Eliminates the per-4-block
# FFI dispatch + offset-buffer memcpy overhead that made em_x4 a net loss
# vs LLVM-pipelined Rust intrinsics.
#
#   void och_asm_em_enc_bulk(
#       uint8_t *dst,            // rdi  — nblocks*32 bytes out
#       const uint8_t *src,      // rsi  — nblocks*32 bytes in
#       size_t nblocks,          // rdx  — multiple of 4, >= 4
#       const uint8_t *l_table,  // rcx  — L[][32], indexed by ntz(i)
#       uint8_t *off,            // r8   — running 32B offset, in/out
#       uint32_t *i_ptr,         // r9   — running counter, in/out (>=1)
#       uint8_t *checksum);      // stk  — 16B XOR accum, in/out
#
# Register plan:
#   xmm0..7   — 4 blocks × 2 lanes (live across rounds)
#   xmm8..11  — round temps (dead outside areion256_x4_body)
#   xmm12     — zero (RC1)
#   xmm13     — RC0 scratch (dead outside rounds; reused pre/post)
#   xmm14/15  — running offset lo/hi (persistent across iterations)
#   rax       — running i   rbx — checksum ptr   r10 — ntz scratch
#   r11       — .Larc base

# Emit pre-XOR for one of 4 blocks: advance running off by L[ntz(i)],
# spill to stack slot b, load src block, XOR off into it, i++.
sub bulk_preblock {
    my ($b, $x0, $x1) = @_;
    my $soff = 32*$b;     # stack slot
    my $moff = 32*$b;     # src/dst stride
    return <<___;
	bsf		%eax, %r10d
	shl		\$5, %r10
	movdqu		(%rcx,%r10), $ta
	movdqu		16(%rcx,%r10), $tb
	pxor		$ta, %xmm14
	pxor		$tb, %xmm15
	movdqa		%xmm14, ${soff}(%rsp)
	movdqa		%xmm15, ${soff}+16(%rsp)
	movdqu		${moff}(%rsi), $x0
	movdqu		${moff}+16(%rsi), $x1
	pxor		%xmm14, $x0
	pxor		%xmm15, $x1
	inc		%eax
___
}

# Post-XOR block b from its spilled offset, store to dst.
sub bulk_postblock {
    my ($b, $x0, $x1) = @_;
    my $soff = 32*$b;
    my $moff = 32*$b;
    return <<___;
	pxor		${soff}(%rsp), $x0
	pxor		${soff}+16(%rsp), $x1
	movdqu		$x0, ${moff}(%rdi)
	movdqu		$x1, ${moff}+16(%rdi)
___
}

# Checksum: XOR first 16B of each source block into *rbx.
# enc: src is plaintext (rsi-relative, pre-Areion).
# dec: src is recovered plaintext (in block regs x0 post-XOR).
sub bulk_checksum_enc {
    return <<___;
	movdqu		(%rbx), $rc
	movdqu		(%rsi), $ta
	pxor		$ta, $rc
	movdqu		32(%rsi), $ta
	pxor		$ta, $rc
	movdqu		64(%rsi), $ta
	pxor		$ta, $rc
	movdqu		96(%rsi), $ta
	pxor		$ta, $rc
	movdqu		$rc, (%rbx)
___
}

sub bulk_checksum_dec {
    # After post-XOR, x0-lanes of each block hold recovered pt lo-16.
    return <<___;
	movdqu		(%rbx), $rc
	pxor		$a0, $rc
	pxor		$b0, $rc
	pxor		$c0, $rc
	pxor		$d0, $rc
	movdqu		$rc, (%rbx)
___
}

# Generate one bulk function. dec: checksum after rounds, from regs.
sub gen_bulk {
    my $dir = shift;  # "enc" or "dec"
    my $name = "och_asm_em_${dir}_bulk";
    my $areion = areion256_x4_body($dir eq "enc" ? "fwd" : "bwd");

    my $out = <<___;
.globl	$name
.type	$name,\@function,7
.align	32
$name:
.cfi_startproc
___
    $out .= "\tendbranch\n" unless $win64;
    # Prologue: save rbx, carve 128B aligned stack buffer.
    # On entry rsp is 8 mod 16; push → 0 mod 16; sub 128 → 0 mod 16. Good.
    $out .= <<___;
	push		%rbx
.cfi_push	%rbx
	sub		\$128, %rsp
.cfi_adjust_cfa_offset 128
	mov		128+16(%rsp), %rbx
	lea		.Larc(%rip), %r11
	pxor		$z, $z
	movdqu		(%r8), %xmm14
	movdqu		16(%r8), %xmm15
	mov		(%r9), %eax

.L${dir}_loop:
___
    # enc: checksum from plaintext (src) BEFORE encryption.
    $out .= bulk_checksum_enc() if $dir eq "enc";

    # 4× pre-XOR (advances off, spills to stack, loads block ^ off).
    $out .= bulk_preblock(0, $a0, $a1);
    $out .= bulk_preblock(1, $b0, $b1);
    $out .= bulk_preblock(2, $c0, $c1);
    $out .= bulk_preblock(3, $d0, $d1);

    # 10-round 4-way Areion.
    $out .= $areion;

    # 4× post-XOR from spilled offsets, store to dst.
    $out .= bulk_postblock(0, $a0, $a1);
    $out .= bulk_postblock(1, $b0, $b1);
    $out .= bulk_postblock(2, $c0, $c1);
    $out .= bulk_postblock(3, $d0, $d1);

    # dec: checksum from recovered plaintext (block regs) AFTER decryption.
    # NB must come before we clobber a0/b0/c0/d0 — above stores leave them
    # intact, so this is fine.
    $out .= bulk_checksum_dec() if $dir eq "dec";

    $out .= <<___;
	add		\$128, %rsi
	add		\$128, %rdi
	sub		\$4, %rdx
	jnz		.L${dir}_loop

	movdqu		%xmm14, (%r8)
	movdqu		%xmm15, 16(%r8)
	mov		%eax, (%r9)
___
    $out .= clear_scratch();
    # Zero block regs too — they held plaintext.
    $out .= <<___;
	pxor		$a0, $a0
	pxor		$a1, $a1
	pxor		$b0, $b0
	pxor		$b1, $b1
	pxor		$c0, $c0
	pxor		$c1, $c1
	pxor		$d0, $d0
	pxor		$d1, $d1
	pxor		%xmm14, %xmm14
	pxor		%xmm15, %xmm15
	add		\$128, %rsp
.cfi_adjust_cfa_offset -128
	pop		%rbx
.cfi_pop	%rbx
	ret
.cfi_endproc
.size	$name,.-$name
___
    return $out;
}

$code .= gen_bulk("enc");
$code .= gen_bulk("dec");

# --------------------------------------------------------------------------

# No executable stack. xlate passes unknown sections through as-is on ELF.
$code .= ".section\t.note.GNU-stack,\"\",\@progbits\n" unless $win64;

print $code;
close STDOUT or die "error closing STDOUT: $!";
