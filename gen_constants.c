/* CRC Folding Constants Generator
 *
 * Computes the folding constants needed for PCLMULQDQ/PMULL-based CRC.
 *
 * Supports:
 * - CRC64-Jones: polynomial 0xad93d23594c935a9 (reflected)
 * - CRC16-CCITT: polynomial 0x1021 (non-reflected)
 *
 * Based on Intel's whitepaper on fast CRC computation.
 */

#include <stdint.h>
#include <stdio.h>

/* Bit-reflect a 64-bit value */
static uint64_t reflect64(uint64_t x) {
    x = ((x & 0x5555555555555555ULL) << 1) | ((x >> 1) & 0x5555555555555555ULL);
    x = ((x & 0x3333333333333333ULL) << 2) | ((x >> 2) & 0x3333333333333333ULL);
    x = ((x & 0x0F0F0F0F0F0F0F0FULL) << 4) | ((x >> 4) & 0x0F0F0F0F0F0F0F0FULL);
    x = ((x & 0x00FF00FF00FF00FFULL) << 8) | ((x >> 8) & 0x00FF00FF00FF00FFULL);
    x = ((x & 0x0000FFFF0000FFFFULL) << 16) |
        ((x >> 16) & 0x0000FFFF0000FFFFULL);
    return (x << 32) | (x >> 32);
}

/* Compute x^n mod P for 64-bit polynomial (reflected CRC)
 * P is the 65-bit polynomial: x^64 + poly (where poly is 64-bit)
 */
static uint64_t xnmodp64_reflected(unsigned n, uint64_t poly) {
    uint64_t result;

    if (n < 64) {
        return 1ULL << n;
    }

    /* x^64 mod P = poly */
    result = poly;

    if (n == 64) {
        return result;
    }

    /* Compute x^n by repeated multiplication by x */
    for (unsigned i = 64; i < n; i++) {
        uint64_t msb = result >> 63;
        result <<= 1;
        if (msb) {
            result ^= poly;
        }
    }

    return result;
}

/* Compute x^n mod P for 16-bit polynomial (non-reflected CRC)
 * P is the 17-bit polynomial: x^16 + poly (where poly is 16-bit)
 *
 * For non-reflected CRC16, we work in a 64-bit space where the
 * 16-bit CRC occupies the high 16 bits.
 *
 * The polynomial 0x1021 represents x^12 + x^5 + 1 (the lower 16 bits).
 * Full polynomial is x^16 + x^12 + x^5 + 1 = 0x11021
 *
 * Note: This function documents the algorithm but is not currently used
 * as we use a simpler inline computation in main().
 */
__attribute__((unused)) static uint64_t xnmodp16(unsigned n, uint16_t poly) {
    /* For non-reflected CRC16, we compute in a space where
     * the polynomial occupies the HIGH bits.
     *
     * x^16 mod P = poly (in high 16 bits of a 64-bit word)
     * x^17 mod P = x * poly mod P = (poly << 1) XOR (msb ? poly : 0)
     */
    uint64_t result;
    uint64_t poly64 = (uint64_t)poly << 48; /* Polynomial in high position */

    if (n < 16) {
        return 1ULL << (63 - n); /* x^n in high position */
    }

    /* x^16 mod P = poly (in high 16 bits) */
    result = poly64;

    if (n == 16) {
        return result;
    }

    /* Compute x^n by repeated multiplication by x (shift left) */
    for (unsigned i = 16; i < n; i++) {
        uint64_t msb = result >> 63;
        result <<= 1;
        if (msb) {
            result ^= poly64;
        }
    }

    return result;
}

/* CRC64-Jones polynomial (the lower 64 bits, without the x^64 term) */
#define JONES_POLY UINT64_C(0xad93d23594c935a9)

/* CRC16-CCITT polynomial (without the x^16 term) */
#define CCITT_POLY UINT16_C(0x1021)

int main(void) {
    printf("CRC Folding Constants Generator\n");
    printf("================================\n\n");

    /* ====================== CRC64-Jones (Reflected) ====================== */
    printf("=== CRC64-Jones (Reflected) ===\n");
    printf("Polynomial: 0x%016llx\n", (unsigned long long)JONES_POLY);
    printf("Reflected:  0x%016llx\n\n",
           (unsigned long long)reflect64(JONES_POLY));

    uint64_t poly64 = JONES_POLY;

    printf("/* 16-byte folding constants */\n");
    uint64_t rk1 = xnmodp64_reflected(128 + 64 - 1, poly64);
    uint64_t rk2 = xnmodp64_reflected(128 - 1, poly64);
    printf("#define CRC64_RK1 UINT64_C(0x%016llx)  /* x^191 mod P */\n",
           (unsigned long long)rk1);
    printf("#define CRC64_RK2 UINT64_C(0x%016llx)  /* x^127 mod P */\n",
           (unsigned long long)rk2);

    printf("\n/* 128-byte folding constants */\n");
    uint64_t rk3 = xnmodp64_reflected(1024 + 64 - 1, poly64);
    uint64_t rk4 = xnmodp64_reflected(1024 - 1, poly64);
    printf("#define CRC64_RK3 UINT64_C(0x%016llx)  /* x^1087 mod P */\n",
           (unsigned long long)rk3);
    printf("#define CRC64_RK4 UINT64_C(0x%016llx)  /* x^1023 mod P */\n",
           (unsigned long long)rk4);

    printf("\n/* Final reduction constants */\n");
    uint64_t rk5 = xnmodp64_reflected(96 - 1, poly64);
    uint64_t rk6 = xnmodp64_reflected(64 - 1, poly64);
    printf("#define CRC64_RK5 UINT64_C(0x%016llx)  /* x^95 mod P */\n",
           (unsigned long long)rk5);
    printf("#define CRC64_RK6 UINT64_C(0x%016llx)  /* x^63 mod P */\n",
           (unsigned long long)rk6);

    printf("\n/* 8-way reduction constants (from Intel ISA-L) */\n");
    printf("/* These reduce 8 accumulators to 1 after 128-byte folding */\n");

    /* ====================== CRC16-CCITT (Non-Reflected) ======================
     */
    printf("\n\n=== CRC16-CCITT (Non-Reflected) ===\n");
    printf("Polynomial: 0x%04x (17-bit: 0x1%04x)\n\n", CCITT_POLY, CCITT_POLY);

    /*
     * For CRC16, we embed the 16-bit CRC in a 64-bit space.
     * The PCLMULQDQ instruction can still be used, but we need to
     * properly position the data and constants.
     *
     * For non-reflected CRC16:
     * - Data is processed MSB-first
     * - CRC occupies the high 16 bits
     * - After PCLMULQDQ, we extract the high 16 bits
     *
     * Folding constants for 128-bit (16-byte) blocks:
     * k1 = x^(128+16) mod P = x^144 mod P
     * k2 = x^128 mod P
     */

    printf("/* 16-byte folding constants (embedded in 64-bit) */\n");

    /* For non-reflected CRC16, we need different constant computation.
     * The constants are x^n mod P, but positioned for PCLMULQDQ use.
     */

    /* Simple computation: x^n mod P(x) where P(x) = x^16 + x^12 + x^5 + 1 */
    uint32_t p16 = 0x11021; /* 17-bit polynomial */

    /* Compute x^144 mod P */
    uint32_t k1_16 = 1;
    for (int i = 0; i < 144; i++) {
        k1_16 <<= 1;
        if (k1_16 & 0x10000) {
            k1_16 ^= p16;
        }
    }

    /* Compute x^128 mod P */
    uint32_t k2_16 = 1;
    for (int i = 0; i < 128; i++) {
        k2_16 <<= 1;
        if (k2_16 & 0x10000) {
            k2_16 ^= p16;
        }
    }

    printf("#define CRC16_K1 UINT64_C(0x%04x)  /* x^144 mod P */\n",
           k1_16 & 0xFFFF);
    printf("#define CRC16_K2 UINT64_C(0x%04x)  /* x^128 mod P */\n",
           k2_16 & 0xFFFF);

    /* Compute constants for 64-byte folding */
    printf("\n/* 64-byte folding constants */\n");

    /* x^(512+16) = x^528 mod P */
    uint32_t k3_16 = 1;
    for (int i = 0; i < 528; i++) {
        k3_16 <<= 1;
        if (k3_16 & 0x10000) {
            k3_16 ^= p16;
        }
    }

    /* x^512 mod P */
    uint32_t k4_16 = 1;
    for (int i = 0; i < 512; i++) {
        k4_16 <<= 1;
        if (k4_16 & 0x10000) {
            k4_16 ^= p16;
        }
    }

    printf("#define CRC16_K3 UINT64_C(0x%04x)  /* x^528 mod P */\n",
           k3_16 & 0xFFFF);
    printf("#define CRC16_K4 UINT64_C(0x%04x)  /* x^512 mod P */\n",
           k4_16 & 0xFFFF);

    /* Barrett reduction constants */
    printf("\n/* Barrett reduction constants */\n");

    /* For Barrett reduction:
     * mu = floor(x^32 / P) for 16-bit CRC
     * This gives us the "inverse" for division
     */
    uint32_t mu = 0;
    uint32_t dividend = 1;
    for (int i = 0; i < 32; i++) {
        dividend <<= 1;
        mu <<= 1;
        if (dividend >= p16) {
            dividend -= p16;
            mu |= 1;
        }
    }

    printf("#define CRC16_MU   UINT64_C(0x%08x)  /* floor(x^32 / P) */\n", mu);
    printf("#define CRC16_POLY UINT64_C(0x%04x)  /* polynomial */\n",
           CCITT_POLY);

    /* Additional constants for 8-way reduction */
    printf("\n/* 8-way reduction constants for 128-byte processing */\n");
    for (int slot = 0; slot < 7; slot++) {
        int bits = (7 - slot) * 128 + 16;
        uint32_t k = 1;
        for (int i = 0; i < bits; i++) {
            k <<= 1;
            if (k & 0x10000) {
                k ^= p16;
            }
        }
        printf("#define CRC16_RK%d UINT64_C(0x%04x)  /* x^%d mod P */\n",
               9 + slot * 2, k & 0xFFFF, bits);

        bits = (7 - slot) * 128;
        k = 1;
        for (int i = 0; i < bits; i++) {
            k <<= 1;
            if (k & 0x10000) {
                k ^= p16;
            }
        }
        printf("#define CRC16_RK%d UINT64_C(0x%04x)  /* x^%d mod P */\n",
               10 + slot * 2, k & 0xFFFF, bits);
    }

    /* Additional constants for 2-way folding (128-bit blocks) */
    printf("\n/* 2-way folding constants (for 128-bit blocks) */\n");

    /* x^192 mod P (for high 64-bit lane) */
    uint32_t k192 = 1;
    for (int i = 0; i < 192; i++) {
        k192 <<= 1;
        if (k192 & 0x10000) {
            k192 ^= p16;
        }
    }
    printf("#define CRC16_K192 UINT64_C(0x%04x)  /* x^192 mod P */\n",
           k192 & 0xFFFF);

    /* x^128 mod P (for low 64-bit lane) - same as K2 */
    printf("#define CRC16_K128 UINT64_C(0x%04x)  /* x^128 mod P */\n",
           k2_16 & 0xFFFF);

    /* x^64 mod P (for final reduction) */
    uint32_t k64 = 1;
    for (int i = 0; i < 64; i++) {
        k64 <<= 1;
        if (k64 & 0x10000) {
            k64 ^= p16;
        }
    }
    printf("#define CRC16_K64 UINT64_C(0x%04x)  /* x^64 mod P */\n",
           k64 & 0xFFFF);

    return 0;
}
