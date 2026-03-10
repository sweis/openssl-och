//! Areion512-Sponge keyed hash.
//!
//! Width = 512 bits, rate = 256 bits, capacity = 256 bits.
//! Matches the OCH reference (`sponge512.c`) exactly, including the
//! call-level 0xff padding quirk (padding only applied per `update()` call
//! when the call's length is not a multiple of 32).

use crate::areion::areion512_forward;

const LABEL_INIT_WITH_KEY: u8 = 0xd0;

#[derive(Clone)]
pub struct Sponge512 {
    state: [u8; 64],
}

impl Sponge512 {
    /// Initialise with a 32-byte key.
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        let mut state = [0u8; 64];
        state[0..32].copy_from_slice(key);
        state[32] = LABEL_INIT_WITH_KEY;
        areion512_forward(&mut state);
        Sponge512 { state }
    }

    /// Absorb `input`. If its length is not a multiple of 32, the final
    /// partial chunk is 0xff-padded (as in the reference). If it *is* a
    /// multiple of 32, no padding is added for this call.
    pub fn update(&mut self, input: &[u8]) {
        let mut i = 0;
        while i + 32 <= input.len() {
            for j in 0..32 {
                self.state[j] ^= input[i + j];
            }
            areion512_forward(&mut self.state);
            i += 32;
        }
        if i < input.len() {
            let rem = input.len() - i;
            debug_assert!(rem < 32);
            let mut excess = [0u8; 32];
            excess[..rem].copy_from_slice(&input[i..]);
            excess[rem] = 0xff;
            for j in 0..32 {
                self.state[j] ^= excess[j];
            }
            areion512_forward(&mut self.state);
        }
    }

    /// Squeeze 32 bytes. Applies one extra permutation before squeeze.
    pub fn finalize(mut self) -> [u8; 32] {
        areion512_forward(&mut self.state);
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.state[0..32]);
        out
    }
}

/// One-shot keyed hash (init + update + final).
pub fn keyed_hash(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut s = Sponge512::new_keyed(key);
    s.update(msg);
    s.finalize()
}
