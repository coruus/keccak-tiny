#include <stdint.h>
#include <stdlib.h>

// Lengths.
#define sponge_bytelen           200
/* sponge_rate == sponge_bytelen - sponge_capacity */
#define sponge_rate              136
/* sponge_security_strength == capacity / 2 == 32B == 256b */
#define sponge_security_strength 64
#define _S(C, F) C##256##_##F

/* The sponge structure.
 */
typedef struct sponge {
  uint64_t a[25];    // the sponge state
  uint64_t _[1];     // 8 bytes of padding (or space for the rate)
  uint64_t flags;    // the hash object's status
  uint64_t position; // the position into the sponge
} keccak_sponge;


/** Initialize a SHAKE instance.
 *
 * @param sponge[out] Pointer to sponge to initialize.
 * @return 0 on success; -1 if the pointer is NULL.
 */
int _S(shake, init) (keccak_sponge* const restrict sponge);

/** Absorb more data into the sponge.
 *
 * @param  sponge[in,out]  Pointer to sponge.
 * @param  in[in]          Input to absorb.
 * @param  inlen[in]       Length of the input.
 * @return 0 on success, < 0 if a pointer is NULL, > 0 if the
 *         sponge has already been finalized, or has not yet
 *         been initialized.
 */
int _S(shake, absorb) (keccak_sponge* const restrict sponge,
                       const uint8_t* const restrict in,
                       const size_t inlen);

/** Squeeze output from the sponge.
 *
 * @param  sponge[in,out]  Pointer to sponge.
 * @param  out[out]        Buffer to write squeezed output into.
 * @param  outlen[in]      Length of output to squeeze.
 * @return 0 on success, < 0 if a pointer is NULL, > 0 if the
 *         sponge has not yet been initialized.
 */

int _S(shake, squeeze) (keccak_sponge* const restrict sponge,
                        uint8_t* const restrict out,
                        const size_t outlen);

/** "Forget" the previous state of the sponge by overwriting
 * security_strength bytes of the state with zeros.
 *
 * @param  sponge[in,out]  Pointer to sponge.
 * @return 0 on success, < 0 if a pointer is NULL, > 0 if the
 *         sponge has not yet been initialized.
 */
int _S(sprng, forget) (keccak_sponge* const restrict sponge);


int _S(sprng, init) (keccak_sponge* const restrict sponge,
                     uint8_t* const entropy,
                     const size_t entropylen);
int _S(sprng, next) (keccak_sponge* const restrict sponge,
                     uint8_t* const entropy,
                     const size_t entropylen);

/** Squeeze output, but don't forget -- i.e., prevent
 * backtracking. Must *always* be followed by a forget
 * function before exiting code that you control.
 */
int _S(sprng, squeeze) (keccak_sponge* const restrict sponge,
                        uint8_t* const restrict out,
                        const size_t outlen);
/** Squeeze output, and then forget, to prevent an attacker
 * from backtracking to the output via the state of the sponge.
 */
int _S(sprng, random) (keccak_sponge* const restrict sponge,
                       uint8_t* const restrict out,
                       const size_t outlen);

// Flags indicating sponge state.
#define FLAG_ABSORBING   UINT64_C(0x53efb6b64647b401)
#define FLAG_SQUEEZING   UINT64_C(0x44a50aed67ba8c04)
#define FLAG_SPONGEPRG   UINT64_C(0xbf0420879da9f2d9)

// Errors.
#define SPONGERR_NULL      -1  /* a passed pointer was NULL             */
#define SPONGERR_RSIZE     -2  /* the passed length is > RSIZE_MAX      */
#define SPONGERR_INVARIANT  1  /* the sponge invariant was violated     */
#define SPONGERR_NOTINIT    2  /* the sponge isn't initalized           */
#define SPONGERR_FINALIZED  3  /* the sponge has already been finalized */


