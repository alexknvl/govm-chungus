#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "secp256k1.h"
#include "secp256k1_recovery.h"

#include "govm.h"

///////////////////////////////////////////////////////////////////////////////
//
///////////////////////////////////////////////////////////////////////////////

#define SHA3_224_DIGEST_SIZE	(224 / 8)
#define SHA3_224_BLOCK_SIZE	(200 - 2 * SHA3_224_DIGEST_SIZE)

#define SHA3_256_DIGEST_SIZE	(256 / 8)
#define SHA3_256_BLOCK_SIZE	(200 - 2 * SHA3_256_DIGEST_SIZE)

#define SHA3_384_DIGEST_SIZE	(384 / 8)
#define SHA3_384_BLOCK_SIZE	(200 - 2 * SHA3_384_DIGEST_SIZE)

#define SHA3_512_DIGEST_SIZE	(512 / 8)
#define SHA3_512_BLOCK_SIZE	(200 - 2 * SHA3_512_DIGEST_SIZE)

struct sha3_state {
	uint64_t		st[25];
	unsigned int	md_len;
	unsigned int	rsiz;
	unsigned int	rsizw;

	unsigned int	partial;
	uint8_t			buf[SHA3_224_BLOCK_SIZE];
};

void sha3_init  (struct sha3_state *sctx, unsigned int digest_sz);
void sha3_update(struct sha3_state *sctx, const uint8_t *data, unsigned int len);
void sha3_final (struct sha3_state *sctx, uint8_t *out);


///////////////////////////////////////////////////////////////////////////////
//
///////////////////////////////////////////////////////////////////////////////

#define KECCAK_ROUNDS 24

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static const uint64_t keccakf_rndc[24] =
{
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccakf_rotc[24] =
{
	1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
	27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
};

static const int keccakf_piln[24] =
{
	10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
	15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
};

// update the state with given number of rounds
static void keccakf(uint64_t st[25], int rounds)
{
	int i, j, round;
	uint64_t t, bc[5];

	for (round = 0; round < rounds; round++) {

		// Theta
		for (i = 0; i < 5; i++) {
			bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
		}

		for (i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
			for (j = 0; j < 25; j += 5) {
				st[j + i] ^= t;
			}
		}

		// Rho Pi
		t = st[1];
		for (i = 0; i < 24; i++) {
			j = keccakf_piln[i];
			bc[0] = st[j];
			st[j] = ROTL64(t, keccakf_rotc[i]);
			t = bc[0];
		}

		//  Chi
		for (j = 0; j < 25; j += 5) {
			for (i = 0; i < 5; i++) {
				bc[i] = st[j + i];
			}
			for (i = 0; i < 5; i++) {
				st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
			}
		}

		//  Iota
		st[0] ^= keccakf_rndc[round];
	}
}

void sha3_init(struct sha3_state *sctx, unsigned int digest_sz)
{
	memset(sctx, 0, sizeof(*sctx));
	sctx->md_len = digest_sz;
	sctx->rsiz = 200 - 2 * digest_sz;
	sctx->rsizw = sctx->rsiz / 8;
}

void sha3_update(struct sha3_state *sctx, const uint8_t *data, unsigned int len)
{
	unsigned int done;
	const uint8_t *src;

	done = 0;
	src = data;

	if ((sctx->partial + len) > (sctx->rsiz - 1)) {
		if (sctx->partial) {
			done = -sctx->partial;
			memcpy(sctx->buf + sctx->partial, data, done + sctx->rsiz);
			src = sctx->buf;
		}

		do {
			unsigned int i;

			for (i = 0; i < sctx->rsizw; i++) {
				sctx->st[i] ^= ((uint64_t *) src)[i];
            }
			keccakf(sctx->st, KECCAK_ROUNDS);

			done += sctx->rsiz;
			src = data + done;
		} while (done + (sctx->rsiz - 1) < len);

		sctx->partial = 0;
	}
	memcpy(sctx->buf + sctx->partial, src, len - done);
	sctx->partial += (len - done);
}

void sha3_final(struct sha3_state *sctx, uint8_t *out)
{
	unsigned int i, inlen = sctx->partial;

	sctx->buf[inlen++] = 0x06; // sha3 standart
	memset(sctx->buf + inlen, 0, sctx->rsiz - inlen);
	sctx->buf[sctx->rsiz - 1] |= 0x80;

	for (i = 0; i < sctx->rsizw; i++)
		sctx->st[i] ^= ((uint64_t *) sctx->buf)[i];

	keccakf(sctx->st, KECCAK_ROUNDS);

//	for (i = 0; i < sctx->rsizw; i++)
//		sctx->st[i] = cpu_to_le64(sctx->st[i]);

	memcpy(out, sctx->st, sctx->md_len);

	memset(sctx, 0, sizeof(*sctx));
}

///////////////////////////////////////////////////////////////////////////////
//
///////////////////////////////////////////////////////////////////////////////

void govm_sha3(
    const uint8_t* data,
    size_t len,
    uint8_t *hash
) {
    struct sha3_state state;
    sha3_init(&state, SHA3_256_DIGEST_SIZE);
    sha3_update(&state, "govm", 4);
    sha3_update(&state, data, len);
    sha3_final(&state, hash);
}

const size_t block_size = sizeof(govm_block_t);
const size_t signature_size = 65;

void govm_block_sign(
    secp256k1_context const * const ctx,
    uint8_t           const * const block,
    size_t                    const block_length,
    uint8_t           const * const seckey,
    uint8_t                 * const result,
    uint8_t                 * const hash
) {
    // assert(block_length == block_size);

    uint8_t hash0[SHA3_256_DIGEST_SIZE];
    govm_sha3(block, block_length, hash0);

    secp256k1_ecdsa_recoverable_signature sig;
    secp256k1_ecdsa_sign_recoverable(ctx, &sig, hash0, seckey, NULL, NULL);
    int recid;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, result + 2, &recid, &sig);
    result[1] = 27 + 4 + recid;

    result[0] = 65;
    memcpy(result + 1 + signature_size, block, block_length);
    govm_sha3(result, 1 + signature_size + block_length, hash);
}

size_t govm_hash_power(uint8_t const * const in, size_t length) {
	size_t out = 0;

    for (size_t i = 0; i < length; i++) {
        out += 8;

        uint8_t item = in[i];
		if (item != 0) {
			while (item > 0) {
				out--;
				item = item >> 1;
			}
			return out;
		}
    }
	return out;
}

SECP256K1_INLINE uint64_t get_uint64_be(uint64_t const * const ptr) {
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        return __builtin_bswap64(*ptr);
    #else
        return *ptr;
    #endif
}

SECP256K1_INLINE void set_uint64_be(uint64_t* const ptr, uint64_t const value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        *ptr = __builtin_bswap64(value);
    #else
        *ptr = value;
    #endif
}

int govm_hash_compare(uint8_t const * const a, uint8_t const * const b) {
	uint64_t av = govm_hash_power(a, 32);
	uint64_t bv = govm_hash_power(b, 32);
    if (av > bv) return -1;
    else if (av < bv) return 1;
    else return 0;
}

size_t govm_block_best(
    secp256k1_context const * const ctx,
    size_t                    const test_count,
    uint8_t           const * const block,
    size_t                    const block_length,
    uint8_t           const * const seckey,
    uint8_t                 * const result,
    uint8_t                 * const hash
) {
    uint8_t hash_tmp[SHA3_256_DIGEST_SIZE];
    secp256k1_ecdsa_recoverable_signature sig;

    uint8_t final[1 + 65 + block_length];
    final[0] = 65;
    memcpy(final + 1 + signature_size, block, block_length);
    memset(hash, 0xFF, SHA3_256_DIGEST_SIZE);

    uint64_t start_nonce = get_uint64_be((uint64_t*)(block + block_length - 8));

	// printf("wtf\n");

    size_t best = 0;
    for (size_t i = 0; i < test_count; i++) {
        // Update nonce in place.
        set_uint64_be((uint64_t*)(final + 1 + signature_size + block_length - 8), start_nonce + i);
        // Sign.
        govm_sha3(final + 1 + signature_size, block_length, hash_tmp);
        secp256k1_ecdsa_sign_recoverable(ctx, &sig, hash_tmp, seckey, NULL, NULL);
        int recid;
        secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, final + 2, &recid, &sig);
        final[1] = 27 + 4 + recid;
        // Compute final hash.
        govm_sha3(final, 1 + signature_size + block_length, hash_tmp);

        // If hash is better, copy it.
        if (govm_hash_compare(hash_tmp, hash) < 0) {
            best = i;
			// printf("smaller=");
			// for (int i = 0; i < 8; i++) printf("%02x", hash_tmp[i]);
			// printf(";\n");

			// printf("  larger=");
			// for (int i = 0; i < 8; i++) printf("%02x", hash[i]);
			// printf(";\n");

			// exit(-1);
            memcpy(hash, hash_tmp, SHA3_256_DIGEST_SIZE);
        }
    }

    // Update nonce in place.
    set_uint64_be((uint64_t*)(final + 1 + signature_size + block_length - 8), start_nonce + best);
    // Sign.
    govm_sha3(final + 1 + signature_size, block_length, hash_tmp);
    secp256k1_ecdsa_sign_recoverable(ctx, &sig, hash_tmp, seckey, NULL, NULL);
    int recid;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, final + 2, &recid, &sig);
    final[1] = 27 + 4 + recid;
    memcpy(result, final, 1 + signature_size + block_length);

    return start_nonce + best;
}