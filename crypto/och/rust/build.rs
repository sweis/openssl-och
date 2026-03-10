//! Build script: generate + assemble crypto/och/asm/areion-x86_64.s.
//!
//! Sets `cfg(och_asm)` when successful; Rust code uses that to enable the
//! 4x-interleaved ASM fast path. When the Perl-asm step fails or the
//! target is not x86_64, the build proceeds without ASM and the pure-Rust
//! path is used.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=OCH_NO_ASM");
    if env::var_os("OCH_NO_ASM").is_some() {
        println!("cargo:warning=och: OCH_NO_ASM set; using pure Rust");
        return;
    }
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    if arch != "x86_64" {
        println!("cargo:warning=och: ASM kernels are x86_64-only; using pure Rust");
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let perl_src = crate_dir.join("../asm/areion-x86_64.pl");
    let xlate = crate_dir.join("../../perlasm/x86_64-xlate.pl");
    let out_s = out_dir.join("areion-x86_64.s");
    let out_o = out_dir.join("areion-x86_64.o");

    println!("cargo:rerun-if-changed={}", perl_src.display());
    println!("cargo:rerun-if-changed={}", xlate.display());

    // 1) perl asm/areion-x86_64.pl elf $OUT_DIR/areion-x86_64.s
    let perl = env::var("PERL").unwrap_or_else(|_| "perl".into());
    let s = Command::new(&perl)
        .arg(&perl_src)
        .arg("elf")
        .arg(&out_s)
        .status();
    match s {
        Ok(st) if st.success() => {}
        _ => {
            println!("cargo:warning=och: perlasm generation failed; using pure Rust");
            return;
        }
    }

    // 2) Assemble with cc.
    let cc = env::var("CC").unwrap_or_else(|_| "cc".into());
    let s = Command::new(&cc)
        .arg("-c")
        .arg(&out_s)
        .arg("-o")
        .arg(&out_o)
        .status();
    match s {
        Ok(st) if st.success() => {}
        _ => {
            println!("cargo:warning=och: assembly of areion-x86_64.s failed; using pure Rust");
            return;
        }
    }

    // 3) Archive and link.
    let lib = out_dir.join("libochasm.a");
    let ar = env::var("AR").unwrap_or_else(|_| "ar".into());
    let s = Command::new(&ar)
        .arg("crs")
        .arg(&lib)
        .arg(&out_o)
        .status();
    match s {
        Ok(st) if st.success() => {}
        _ => {
            println!("cargo:warning=och: ar step failed; using pure Rust");
            return;
        }
    }

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=ochasm");
    println!("cargo:rustc-cfg=och_asm");
}
