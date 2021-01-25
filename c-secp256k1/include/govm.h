#ifndef GOVM_H
#define GOVM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque data structured that holds a parsed ECDSA signature,
 *  supporting pubkey recovery.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 65 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage or transmission, use
 *  the secp256k1_ecdsa_signature_serialize_* and
 *  secp256k1_ecdsa_signature_parse_* functions.
 *
 *  Furthermore, it is guaranteed that identical signatures (including their
 *  recoverability) will have identical representation, so they can be
 *  memcmp'ed.
 */
typedef struct {
    uint64_t time;
	uint8_t previous[32];
	uint8_t parent[32];
	uint8_t left_child[32];
	uint8_t right_child[32];
	uint8_t trans_list_hash[32];
	uint8_t producer[32];
	uint64_t chain;
	uint64_t index;
	uint64_t nonce;
} govm_block_t __attribute__((packed));

/** Parse a compact ECDSA signature (64 bytes + recovery id).
 *
 *  Returns: 1 when the signature could be parsed, 0 otherwise
 *  Args: ctx:     a secp256k1 context object
 *  Out:  sig:     a pointer to a signature object
 *  In:   input64: a pointer to a 64-byte compact signature
 *        recid:   the recovery id (0, 1, 2 or 3)
 */
void govm_sha3(
    const uint8_t* data,
    size_t len,
    uint8_t *hash
);

void govm_block_sign(
    secp256k1_context const * const ctx,
    uint8_t           const * const block,
    size_t                    const block_length,
    uint8_t           const * const seckey,
    uint8_t                 * const result,
    uint8_t                 * const hash
);

size_t govm_hash_power(uint8_t const * const in, size_t length);

size_t govm_block_best(
    secp256k1_context const * const ctx,
    size_t                    const test_count,
    uint8_t           const * const block,
    size_t                    const block_length,
    uint8_t           const * const seckey,
    uint8_t                 * const result,
    uint8_t                 * const hash
);

#ifdef __cplusplus
}
#endif

#endif /* GOVM_H */
