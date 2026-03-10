We want to implement OCH authenticated encryption mode:
1. Review the paper here: [https://eprint.iacr.org/2026/439](https://eprint.iacr.org/2026/439.pdf) . 
2. Be sure to note any links or references to existing implemnetations of OCH mode.
3. Look for any references to test vectors.
4. Add OCH as a mode to OpenSSL. This should live under: https://github.com/openssl/openssl/tree/master/crypto/aes
5. Implement OCH mode in Rust. Do not use the C implementation like the rest of OpenSSL. Figure out how to get the C-based OpenSSL to call Rust. You may need to make Perl-generated ASM changes here: https://github.com/openssl/openssl/tree/master/crypto/aes/asm
6. Verify that OCH mode is working with any test vectors you can locate.
7. Measure the performance of OCH compared to other equivalent AES authenticated modes like GCM and OFB. Also record CTR mode as a baseline, even though it is not authenticated.
8. Ensure all code is clean and not overly verbose.
