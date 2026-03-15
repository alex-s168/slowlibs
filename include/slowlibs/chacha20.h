/*
 * Copyright (c) 2026 Alexander Nutz
 * 0BSD licensed, see below documentation
 *
 * Latest version can be found at:
 * https://git.vxcc.dev/alexander.nutz/slow-libs
 *
 *
 * ======== ChaCha20 stream cihper ========
 *
 * Security considerations:
 * - manually zeroize memory (depending on your application)
 * - length extension attack:
 *   ChaCha20 is only a stream cihper, and, like AES,
 *   does NOT prevent against length extension attacks.
 *   Consider using ChaCha20-Poly1305 instead.
 *
 *
 * Configuration options:
 * - SLOWCRYPT_CHACHA20_IMPL
 * - SLOWCRYPT_CHACHA20_FUNC
 *     will be used in front of every function definition / declaration
 * - uint32_t
 *     if this is not defined, will include <stdint.h>, and use `uint32_t` and `uint8_t`
 *
 *
 * Compatibility:
 *   requires only a C89 compiler.
 *
 *
 * Usage example 1: en-/de- crypt blocks of data
 *     slowcrypt_chacha20 state[2];
 *     uint32_t ctr = 1;
 *     char buf[64];
 *
 *     iterate over blocks {
 *       copy block into buf (can pad with zeros)
 *       slowcrypt_chacha20_block(state, key, ctr, nonce, buf);
 *       ctr += 1;
 *     }
 *
 *     # optionally zeroize memory
 *     slowcrypt_chacha20_deinit(&state[0]);
 *     slowcrypt_chacha20_deinit(&state[1]);
 *     bzero(buf, 64);
 *
 *
 * Usage example 2: CSPRNG (cryptographically secure pseudo random number generator)
 *     slowcrypt_chacha20 state[2];
 *     uint32_t ctr = 1;
 *     char buf[64];
 *
 *     while need random numbers {
 *       slowcrypt_chacha20_init(state, key, block_ctr, nonce);
 *       slowcrypt_chacha20_run(state, &state[1], 20);
 *       slowcrypt_chacha20_serialize(buf, state);
 *       yield buf
 *       ctr += 1;
 *     }
 *
 *     # optionally zeroize memory
 *     slowcrypt_chacha20_deinit(&state[0]);
 *     slowcrypt_chacha20_deinit(&state[1]);
 *     bzero(buf, 64);
 *
 */

/*
 * Copyright (C) 2026 by Alexander Nutz <alexander.nutz@vxcc.dev>
 *
 * Permission to use, copy, modify, and/or distribute this software
 * for any purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT,
 * OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, 
 * NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
 * OF THIS SOFTWARE.
 */

#ifndef SLOWCRYPT_CHACHA20_H
#define SLOWCRYPT_CHACHA20_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef uint32_t
#include <stdint.h>
#endif

typedef struct
{
  uint32_t state[16];
} slowcrypt_chacha20;

/*
 * initialize state, run 20 iterations, serialize, xor data inplace
 *
 * does NOT zeroize states! zeroize manually when done.
 */
void slowcrypt_chacha20_block(slowcrypt_chacha20 state[2],
                              uint8_t const key[32],
                              uint32_t block_ctr,
                              uint8_t const nonce[12],
                              uint8_t data[64]);

/*
 * Run HChaCha, a (bad) fixed-input "hash" function (see /doc/cacha20.md)
 *
 * does NOT zeroize state! zeroize manually when done.
 *
 * Parameters:
 * - rounds: 20 for HChaCha20
 */
void slowcrypt_hchacha(slowcrypt_chacha20* state,
                       uint8_t const key[32],
                       uint8_t const nonce[16],
                       uint8_t hash[32],
                       int rounds);

/* call this to zero out memory */
void slowcrypt_chacha20_deinit(slowcrypt_chacha20* state);

void slowcrypt_chacha20_init(slowcrypt_chacha20* state,
                             uint8_t const key[32],
                             uint32_t block_ctr,
                             uint8_t const nonce[12]);

void slowcrypt_chacha20_serialize(uint8_t buf[64],
                                  slowcrypt_chacha20 const* state);

void slowcrypt_chacha20_serialize_xor(uint8_t buf[64],
                                      slowcrypt_chacha20 const* state);

void slowcrypt_chacha20_rounds(slowcrypt_chacha20* state, int num_rounds);

/* Runs the rounds, then XORs */
void slowcrypt_chacha20_run(slowcrypt_chacha20* state,
                            slowcrypt_chacha20* swap,
                            int num_rounds);

/*
 * Run KChaCha, a variable-input hash function (see /doc/cacha20.md)
 *
 * Parameters:
 * - protocol_constant:
 *     You should not reuse protocol constants across different parts of your app.
 *     This is NOT allowed to be ZERO!
 *
 * - rounds:
 *     Recommended: 20, 12, or 8
 *
 * - unpadded:
 *     Run UnpaddedKChaCha instead of KChaCha.
 *
 *
 * Security: Only these applications are currently permitted!!
 * - cryptographic hash function of per-protocol fixed-length high-entropy data:
 *     This requires at least 12 rounds, however 20 are recomended.
 *
 *     Examples:
 *     - Curve25519 key exchange
 *
 * - low-security applications, such as a hash-function primitive
 *   inside a memory-dependent hash function, used for for example proof-of-work challenges.
 *   This is only permitted if some high-entropy salt is added into the hash function,
 *   optimally before the data.
 *
 *   Examples:
 *   - use as hash function inside balloon-hash, for proof-of-work challenges
 *   - use as hash function inside balloon-hash, combined with lots of high-entropy salt,
 *     and high balloon-hash memory and iteration parameters,
 *     for use in password key derive applications.
 *     This requires at least 12 rounds, however 20 are recommended.
 *
 * - non-cryptographic hash function applications:
 *   - Trusted file chcecksumming, with a lower round parameter.
 *   - ...
 */
void slowcrypt_kchacha(uint8_t out[32],
                       uint8_t const protocol_constant[16],
                       uint8_t const data[],
                       unsigned data_len,
                       int rounds,
                       int unpadded);

/**
 *
 * Returns:
 * - 0 on success
 */
int slowcrypt_balloon_kchacha(uint8_t out[32],
                              uint8_t const protocol_constant[16],
                              uint8_t const password[],
                              unsigned password_len,
                              uint8_t const salt[],
                              unsigned salt_len,
                              unsigned buffer_size,
                              unsigned balloon_rounds,
                              unsigned kchacha_rounds,
                              int unpadded);

/*
 * Arguments:
 * - `key`:
*      256-bit session integrity key
 *
 * - `nonce` and `nonce_len`:
 *     This MUST be unique per invocation with the same key, so it MUST NOT be
 *     randomly generated.  A counter is a good way to implement this,
 *     but other methods, such as a Linear Feedback Shift Register (LFSR)
 *     are also acceptable.
 *     If this is only 8 bytes, 4 zero bytes will be prepended.
 *
 * Contracts:
 * - `nonce_len == 8 || nonce_len == 12`
 */
void slowcrypt_chacha20_poly1305_key_gen(uint8_t out[32],
                                         uint8_t const key[32],
                                         uint8_t const* nonce,
                                         int nonce_len);

#define SLOWCRYPT_CHACHA20_LAST32(n, bits) (((uint32_t)(n)) >> (32 - (bits)))

#define SLOWCRYPT_CHACHA20_ROL32(n, by) \
  ((((uint32_t)(n)) << (by)) | SLOWCRYPT_CHACHA20_LAST32((n), (by)))

#define SLOWCRYPT_CHACHA20_QROUND(state, a, b, c, d)   \
  do {                                                 \
    state[a] += state[b];                              \
    state[d] ^= state[a];                              \
    state[d] = SLOWCRYPT_CHACHA20_ROL32(state[d], 16); \
                                                       \
    state[c] += state[d];                              \
    state[b] ^= state[c];                              \
    state[b] = SLOWCRYPT_CHACHA20_ROL32(state[b], 12); \
                                                       \
    state[a] += state[b];                              \
    state[d] ^= state[a];                              \
    state[d] = SLOWCRYPT_CHACHA20_ROL32(state[d], 8);  \
                                                       \
    state[c] += state[d];                              \
    state[b] ^= state[c];                              \
    state[b] = SLOWCRYPT_CHACHA20_ROL32(state[b], 7);  \
  } while (0)

#ifdef __cplusplus
}
#endif

#endif
