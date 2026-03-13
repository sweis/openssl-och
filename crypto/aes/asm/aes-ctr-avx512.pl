#! /usr/bin/env perl
# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# AES-CTR32 encryption with Intel(R) VAES on AVX-512.
#
# Processes 16 blocks (256 bytes) per iteration using 4 ZMM registers,
# each carrying 4 independent 128-bit AES states through the vaesenc pipeline.
# The 32-bit big-endian counter is tracked in byte-swapped (little-endian)
# form so vpaddd can increment it; a vpshufb on each iteration restores the
# wire format before encryption.  The caller (CRYPTO_ctr128_encrypt_ctr32)
# guarantees the counter never wraps within one call, so no carry handling
# is needed.
#
# Compared to the XMM-only aesni_ctr32_encrypt_blocks (8 blocks/iter on
# 128-bit registers), this kernel has 4x the register width and 2x the
# loop unroll.

$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$avx512vaes=0;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

if (`$ENV{CC} -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1`
        =~ /GNU assembler version ([2-9]\.[0-9]+)/) {
    $avx512vaes = ($1>=2.30);
}

if (!$avx512vaes && $win64 && ($flavour =~ /nasm/ || $ENV{ASM} =~ /nasm/) &&
       `nasm -v 2>&1` =~ /NASM version ([2-9]\.[0-9]+)(?:\.([0-9]+))?/) {
    $avx512vaes = ($1==2.13 && $2>=3) + ($1>=2.14);
}

if (!$avx512vaes && $win64 && ($flavour =~ /masm/ || $ENV{ASM} =~ /ml64/) &&
       `ml64 2>&1` =~ /Version ([0-9]+\.[0-9]+)\./) {
    $avx512vaes = ($1>=14.16);
}

if (!$avx512vaes && `$ENV{CC} -v 2>&1`
    =~ /(Apple)?\s*((?:clang|LLVM) version|.*based on LLVM) ([0-9]+)\.([0-9]+)\.([0-9]+)?/) {
    my $ver = $3 + $4/100.0 + $5/10000.0;
    if ($1) {
        $avx512vaes = ($ver>=10.0001)
    } else {
        $avx512vaes = ($ver>=7.0);
    }
}

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT=*OUT;

$code=".text\n";

if ($avx512vaes) {

$code.=<<___;
.extern  OPENSSL_ia32cap_P

#################################################################
# int ossl_aes_ctr32_vaes_eligible(void);
#
# Returns non-zero when AVX512F+DQ+BW and VAES are all available.
#################################################################
.globl   ossl_aes_ctr32_vaes_eligible
.type    ossl_aes_ctr32_vaes_eligible,\@abi-omnipotent
.balign  32
ossl_aes_ctr32_vaes_eligible:
.cfi_startproc
    endbranch
    mov  OPENSSL_ia32cap_P+8(%rip),%ecx
    xor  %eax,%eax
    # AVX512BW (bit30) + AVX512DQ (bit17) + AVX512F (bit16)
    and  \$0x40030000,%ecx
    cmp  \$0x40030000,%ecx
    jne  .Lctr32_vaes_eligible_done
    mov  OPENSSL_ia32cap_P+12(%rip),%ecx
    # VAES (bit 9 of word 3)
    and  \$0x200,%ecx
    cmp  \$0x200,%ecx
    cmove %ecx,%eax
.Lctr32_vaes_eligible_done:
    ret
.cfi_endproc
.size ossl_aes_ctr32_vaes_eligible,.-ossl_aes_ctr32_vaes_eligible
___

# ---- register map ----
my ($inp,$out,$blocks,$key,$ivp) = ("%rdi","%rsi","%rdx","%rcx","%r8");
my $rounds = "%r10d";
my $le_ctr = "%r11d";          # scalar 32-bit counter in native (LE) form

# Data registers (low 16, must preserve xmm6-9 on win64)
my @ST   = map("%zmm$_",(0..3));        # AES state: BE counter -> keystream
my @STx  = map("%xmm$_",(0..3));
my @CTR  = map("%zmm$_",(4..7));        # LE-form counters, persistent
my @CTRx = map("%xmm$_",(4..7));
my $BSWAP = "%zmm8";                    # byte-swap shuffle mask
my $BSWAPx= "%xmm8";
my $ADD16 = "%zmm9";                    # +16 in all 4 low dwords

# Round keys live in zmm17..zmm31 (EVEX-only, caller-saved everywhere)
my @RK = map("%zmm$_",(17..31));
my @RKx= map("%xmm$_",(17..31));

my $win64_save = 4*16;  # xmm6..xmm9

# ---- AES round sequence for four ZMM states ----
# Emits pre-whitening, 9 rounds, conditional rounds 10..13, and aesenclast.
# Input/output is in @ST[0..3].  Round keys must already be in @RK.
sub vaes_rounds_4z {
    my ($label)=@_;
$code.=<<___;
    vpxord      $RK[0],$ST[0],$ST[0]
    vpxord      $RK[0],$ST[1],$ST[1]
    vpxord      $RK[0],$ST[2],$ST[2]
    vpxord      $RK[0],$ST[3],$ST[3]
___
    for my $r (1..9) {
$code.=<<___;
    vaesenc     $RK[$r],$ST[0],$ST[0]
    vaesenc     $RK[$r],$ST[1],$ST[1]
    vaesenc     $RK[$r],$ST[2],$ST[2]
    vaesenc     $RK[$r],$ST[3],$ST[3]
___
    }
$code.=<<___;
    cmp         \$9,$rounds
    ja          ${label}_192_256
    vaesenclast $RK[10],$ST[0],$ST[0]
    vaesenclast $RK[10],$ST[1],$ST[1]
    vaesenclast $RK[10],$ST[2],$ST[2]
    vaesenclast $RK[10],$ST[3],$ST[3]
    jmp         ${label}_done
.balign 32
${label}_192_256:
    vaesenc     $RK[10],$ST[0],$ST[0]
    vaesenc     $RK[10],$ST[1],$ST[1]
    vaesenc     $RK[10],$ST[2],$ST[2]
    vaesenc     $RK[10],$ST[3],$ST[3]
    vaesenc     $RK[11],$ST[0],$ST[0]
    vaesenc     $RK[11],$ST[1],$ST[1]
    vaesenc     $RK[11],$ST[2],$ST[2]
    vaesenc     $RK[11],$ST[3],$ST[3]
    cmp         \$11,$rounds
    ja          ${label}_256
    vaesenclast $RK[12],$ST[0],$ST[0]
    vaesenclast $RK[12],$ST[1],$ST[1]
    vaesenclast $RK[12],$ST[2],$ST[2]
    vaesenclast $RK[12],$ST[3],$ST[3]
    jmp         ${label}_done
.balign 32
${label}_256:
    vaesenc     $RK[12],$ST[0],$ST[0]
    vaesenc     $RK[12],$ST[1],$ST[1]
    vaesenc     $RK[12],$ST[2],$ST[2]
    vaesenc     $RK[12],$ST[3],$ST[3]
    vaesenc     $RK[13],$ST[0],$ST[0]
    vaesenc     $RK[13],$ST[1],$ST[1]
    vaesenc     $RK[13],$ST[2],$ST[2]
    vaesenc     $RK[13],$ST[3],$ST[3]
    vaesenclast $RK[14],$ST[0],$ST[0]
    vaesenclast $RK[14],$ST[1],$ST[1]
    vaesenclast $RK[14],$ST[2],$ST[2]
    vaesenclast $RK[14],$ST[3],$ST[3]
.balign 32
${label}_done:
___
}

# Single-ZMM version (4 blocks)
sub vaes_rounds_1z {
    my ($label)=@_;
$code.=<<___;
    vpxord      $RK[0],$ST[0],$ST[0]
___
    for my $r (1..9) {
        $code.="    vaesenc     $RK[$r],$ST[0],$ST[0]\n";
    }
$code.=<<___;
    cmp         \$9,$rounds
    ja          ${label}_192_256
    vaesenclast $RK[10],$ST[0],$ST[0]
    jmp         ${label}_done
.balign 32
${label}_192_256:
    vaesenc     $RK[10],$ST[0],$ST[0]
    vaesenc     $RK[11],$ST[0],$ST[0]
    cmp         \$11,$rounds
    ja          ${label}_256
    vaesenclast $RK[12],$ST[0],$ST[0]
    jmp         ${label}_done
.balign 32
${label}_256:
    vaesenc     $RK[12],$ST[0],$ST[0]
    vaesenc     $RK[13],$ST[0],$ST[0]
    vaesenclast $RK[14],$ST[0],$ST[0]
.balign 32
${label}_done:
___
}

# Single-XMM version (1 block)
sub vaes_rounds_1x {
    my ($label)=@_;
$code.=<<___;
    vpxord      $RKx[0],$STx[0],$STx[0]
___
    for my $r (1..9) {
        $code.="    vaesenc     $RKx[$r],$STx[0],$STx[0]\n";
    }
$code.=<<___;
    cmp         \$9,$rounds
    ja          ${label}_192_256
    vaesenclast $RKx[10],$STx[0],$STx[0]
    jmp         ${label}_done
.balign 32
${label}_192_256:
    vaesenc     $RKx[10],$STx[0],$STx[0]
    vaesenc     $RKx[11],$STx[0],$STx[0]
    cmp         \$11,$rounds
    ja          ${label}_256
    vaesenclast $RKx[12],$STx[0],$STx[0]
    jmp         ${label}_done
.balign 32
${label}_256:
    vaesenc     $RKx[12],$STx[0],$STx[0]
    vaesenc     $RKx[13],$STx[0],$STx[0]
    vaesenclast $RKx[14],$STx[0],$STx[0]
.balign 32
${label}_done:
___
}

$code.=<<___;
#################################################################
# void ossl_aes_ctr32_encrypt_blocks_vaes(
#     const unsigned char *in,    # rdi
#     unsigned char *out,         # rsi
#     size_t blocks,              # rdx
#     const void *key,            # rcx   (AES_KEY*)
#     const unsigned char *ivec); # r8
#
# Handles only complete blocks. Operates on the 32-bit big-endian counter
# in ivec[12..15]. Does not update *ivec.
#################################################################
.globl   ossl_aes_ctr32_encrypt_blocks_vaes
.type    ossl_aes_ctr32_encrypt_blocks_vaes,\@function,5
.balign  64
ossl_aes_ctr32_encrypt_blocks_vaes:
.cfi_startproc
    endbranch
    test    $blocks,$blocks
    jz      .Lctr32_vaes_ret
___
$code.=<<___ if ($win64);
    sub     \$$win64_save,%rsp
.cfi_adjust_cfa_offset $win64_save
    vmovdqu %xmm6,0x00(%rsp)
    vmovdqu %xmm7,0x10(%rsp)
    vmovdqu %xmm8,0x20(%rsp)
    vmovdqu %xmm9,0x30(%rsp)
___
$code.=<<___;
    # Broadcast round keys to all four lanes.
    mov             240($key),$rounds
    vbroadcasti32x4 0x00($key),$RK[0]
    vbroadcasti32x4 0x10($key),$RK[1]
    vbroadcasti32x4 0x20($key),$RK[2]
    vbroadcasti32x4 0x30($key),$RK[3]
    vbroadcasti32x4 0x40($key),$RK[4]
    vbroadcasti32x4 0x50($key),$RK[5]
    vbroadcasti32x4 0x60($key),$RK[6]
    vbroadcasti32x4 0x70($key),$RK[7]
    vbroadcasti32x4 0x80($key),$RK[8]
    vbroadcasti32x4 0x90($key),$RK[9]
    vbroadcasti32x4 0xa0($key),$RK[10]
    vbroadcasti32x4 0xb0($key),$RK[11]
    vbroadcasti32x4 0xc0($key),$RK[12]
    vbroadcasti32x4 0xd0($key),$RK[13]
    vbroadcasti32x4 0xe0($key),$RK[14]

    # Extract 32-bit counter and byte-swap to native order; the
    # caller owns *ivec so we track the running value in a GPR.
    mov             12($ivp),$le_ctr
    bswap           $le_ctr

    vmovdqa64       .Lctr32_bswap_mask(%rip),$BSWAP
    vbroadcasti32x4 ($ivp),$CTR[0]
    vpshufb         $BSWAP,$CTR[0],$CTR[0]
    # lanes now hold the IV with the 32-bit counter in the low dword (LE)
    vpaddd          .Lctr32_add_0123(%rip),$CTR[0],$CTR[0]
    vmovdqa64       .Lctr32_add_4444(%rip),$ADD16
    vpaddd          $ADD16,$CTR[0],$CTR[1]
    vpaddd          $ADD16,$CTR[1],$CTR[2]
    vpaddd          $ADD16,$CTR[2],$CTR[3]
    vmovdqa64       .Lctr32_add_16(%rip),$ADD16

    cmp             \$16,$blocks
    jb              .Lctr32_vaes_tail4

.balign 32
.Lctr32_vaes_loop16:
    # Restore big-endian wire format for encryption.
    vpshufb     $BSWAP,$CTR[0],$ST[0]
    vpshufb     $BSWAP,$CTR[1],$ST[1]
    vpshufb     $BSWAP,$CTR[2],$ST[2]
    vpshufb     $BSWAP,$CTR[3],$ST[3]
___
    &vaes_rounds_4z(".Lctr32_vaes_r16");
$code.=<<___;
    # keystream XOR plaintext
    vpxord      0x00($inp),$ST[0],$ST[0]
    vpxord      0x40($inp),$ST[1],$ST[1]
    vpxord      0x80($inp),$ST[2],$ST[2]
    vpxord      0xc0($inp),$ST[3],$ST[3]
    vmovdqu64   $ST[0],0x00($out)
    vmovdqu64   $ST[1],0x40($out)
    vmovdqu64   $ST[2],0x80($out)
    vmovdqu64   $ST[3],0xc0($out)

    # advance counters and pointers
    vpaddd      $ADD16,$CTR[0],$CTR[0]
    vpaddd      $ADD16,$CTR[1],$CTR[1]
    vpaddd      $ADD16,$CTR[2],$CTR[2]
    vpaddd      $ADD16,$CTR[3],$CTR[3]
    add         \$16,$le_ctr
    add         \$0x100,$inp
    add         \$0x100,$out
    sub         \$16,$blocks
    cmp         \$16,$blocks
    jae         .Lctr32_vaes_loop16

.Lctr32_vaes_tail4:
    cmp         \$4,$blocks
    jb          .Lctr32_vaes_tail1

.balign 32
.Lctr32_vaes_loop4:
    vpshufb     $BSWAP,$CTR[0],$ST[0]
___
    &vaes_rounds_1z(".Lctr32_vaes_r4");
$code.=<<___;
    vpxord      ($inp),$ST[0],$ST[0]
    vmovdqu64   $ST[0],($out)
    vpaddd      .Lctr32_add_4444(%rip),$CTR[0],$CTR[0]
    add         \$4,$le_ctr
    add         \$0x40,$inp
    add         \$0x40,$out
    sub         \$4,$blocks
    cmp         \$4,$blocks
    jae         .Lctr32_vaes_loop4

.Lctr32_vaes_tail1:
    test        $blocks,$blocks
    jz          .Lctr32_vaes_cleanup

    # Rebuild a single-block counter: high 12 bytes from ivec,
    # low 4 bytes = bswap($le_ctr).
    vmovdqu     ($ivp),$CTRx[0]
    bswap       $le_ctr
    vpinsrd     \$3,$le_ctr,$CTRx[0],$CTRx[0]
    bswap       $le_ctr

.balign 32
.Lctr32_vaes_loop1:
    vmovdqa     $CTRx[0],$STx[0]
___
    &vaes_rounds_1x(".Lctr32_vaes_r1");
$code.=<<___;
    vpxord      ($inp),$STx[0],$STx[0]
    vmovdqu     $STx[0],($out)
    # increment scalar counter and patch it into CTR[0] for the next block
    add         \$1,$le_ctr
    bswap       $le_ctr
    vpinsrd     \$3,$le_ctr,$CTRx[0],$CTRx[0]
    bswap       $le_ctr
    add         \$0x10,$inp
    add         \$0x10,$out
    sub         \$1,$blocks
    jnz         .Lctr32_vaes_loop1

.Lctr32_vaes_cleanup:
    vpxord      $ST[0],$ST[0],$ST[0]
    vpxord      $ST[1],$ST[1],$ST[1]
    vpxord      $ST[2],$ST[2],$ST[2]
    vpxord      $ST[3],$ST[3],$ST[3]
    vpxord      $CTR[0],$CTR[0],$CTR[0]
    vpxord      $CTR[1],$CTR[1],$CTR[1]
    vpxord      $CTR[2],$CTR[2],$CTR[2]
    vpxord      $CTR[3],$CTR[3],$CTR[3]
    vzeroupper
___
$code.=<<___ if ($win64);
    vmovdqu 0x00(%rsp),%xmm6
    vmovdqu 0x10(%rsp),%xmm7
    vmovdqu 0x20(%rsp),%xmm8
    vmovdqu 0x30(%rsp),%xmm9
    add     \$$win64_save,%rsp
.cfi_adjust_cfa_offset -$win64_save
___
$code.=<<___;
.Lctr32_vaes_ret:
    ret
.cfi_endproc
.size ossl_aes_ctr32_encrypt_blocks_vaes,.-ossl_aes_ctr32_encrypt_blocks_vaes
___

$code.=<<___;
.section .rodata
.balign 64
# vpshufb mask: reverse all 16 bytes in each 128-bit lane.  After applying
# this to the IV, bytes 12..15 (the BE counter) land in bytes 3..0, i.e. the
# low dword now holds the counter in little-endian.
.Lctr32_bswap_mask:
    .quad 0x08090A0B0C0D0E0F, 0x0001020304050607
    .quad 0x08090A0B0C0D0E0F, 0x0001020304050607
    .quad 0x08090A0B0C0D0E0F, 0x0001020304050607
    .quad 0x08090A0B0C0D0E0F, 0x0001020304050607
.balign 64
.Lctr32_add_0123:
    .quad 0x0000000000000000, 0x0000000000000000
    .quad 0x0000000000000001, 0x0000000000000000
    .quad 0x0000000000000002, 0x0000000000000000
    .quad 0x0000000000000003, 0x0000000000000000
.balign 64
.Lctr32_add_4444:
    .quad 0x0000000000000004, 0x0000000000000000
    .quad 0x0000000000000004, 0x0000000000000000
    .quad 0x0000000000000004, 0x0000000000000000
    .quad 0x0000000000000004, 0x0000000000000000
.balign 64
.Lctr32_add_16:
    .quad 0x0000000000000010, 0x0000000000000000
    .quad 0x0000000000000010, 0x0000000000000000
    .quad 0x0000000000000010, 0x0000000000000000
    .quad 0x0000000000000010, 0x0000000000000000
.text
___

} else {
# Assembler too old for VAES encoding — emit eligible() returning 0 so the
# provider dispatch falls through to aesni_ctr32_encrypt_blocks.
$code.=<<___;
.globl   ossl_aes_ctr32_vaes_eligible
.type    ossl_aes_ctr32_vaes_eligible,\@abi-omnipotent
ossl_aes_ctr32_vaes_eligible:
    xor %eax,%eax
    ret
.size ossl_aes_ctr32_vaes_eligible,.-ossl_aes_ctr32_vaes_eligible
___
}

print $code;

close STDOUT or die "error closing STDOUT: $!";
