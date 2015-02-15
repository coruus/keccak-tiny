#ifndef _SHAKE256_H
#include <stdint.h>
#include <stdlib.h>

#define sponge_bytelen 200
/* sponge_rate == sponge_bytelen - sponge_capacity */
#define sponge_rate 136
/* sponge_security_strength == capacity / 2 == 32B == 256b */
#define sponge_security_strength 64

/* The sponge structure. Callers must treat it as opaque.
 *
 * You may want to change this to use a type with maximal
 * alignment for your target.
 */
#ifndef _KECCAK_SPONGE_INTERNAL
#define keccak_sponge keccak_sponge_opaque
#endif
typedef struct sponge { uint64_t _[28]; } keccak_sponge_opaque;

/** Shake256.
 *
 * @param out [out]    Pointer to output buffer.
 * @param outlen [in]  Length of output to squeeze.
 * @param in [in]      Pointer to input buffer.
 * @param inlen [in]   Length of input to absorb.
 */
int shake256(uint8_t* const out, const size_t outlen,
             const uint8_t* const in, const size_t inlen);

/** Initialize a SHAKE instance.
 *
 * @param sponge [out] Pointer to sponge to initialize.
 * @return 0 on success; -1 if the pointer is NULL.
 */
int shake256_init(keccak_sponge* const restrict sponge);

/** Absorb more data into the sponge.
 *
 * @param  sponge [in,out]  Pointer to sponge.
 * @param  in [in]          Input to absorb.
 * @param  inlen [in]       Length of the input.
 * @return 0 on success, < 0 if a pointer is NULL, > 0 if the
 *         sponge has already been finalized, or has not yet
 *         been initialized.
 */
int shake256_absorb(keccak_sponge* const restrict sponge,
                    const uint8_t* const restrict in,
                    const size_t inlen);

/** Squeeze output from the sponge.
 *
 * @param  sponge [in,out]  Pointer to sponge.
 * @param  out [out]        Buffer to write squeezed output into.
 * @param  outlen [in]      Length of output to squeeze.
 * @return 0 on success, < 0 if a pointer is NULL, > 0 if the
 *         sponge has not yet been initialized.
 */
int shake256_squeeze(keccak_sponge* const restrict sponge,
                     uint8_t* const restrict out,
                     const size_t outlen);

int mac_init(keccak_sponge* const restrict sponge,
             const uint8_t* const key,
             const size_t keylen);
int mac_cached(keccak_sponge* const restrict sponge,
               const uint8_t* const state);
int mac_cache_key(uint64_t* const state,
                  const uint8_t* const key,
                  const size_t keylen);

#define mac_absorb shake256_absorb
#define mac_squeeze shake256_squeeze
#define mac_state keccak_sponge

// Errors.
#define SPONGERR_NULL -1     /* a passed pointer was NULL             */
#define SPONGERR_RSIZE -2    /* the passed length is > RSIZE_MAX      */
#define SPONGERR_INVARIANT 1 /* the sponge invariant was violated     */
#define SPONGERR_NOTINIT 2   /* the sponge isn't initalized           */
#define SPONGERR_FINALIZED 3 /* the sponge has already been finalized */



#endif
