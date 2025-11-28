/* Comprehensive CRC Test Suite
 *
 * Tests correctness of all CRC implementations including SIMD versions.
 * All SIMD implementations must match the reference implementations in
 * crc64speed.c (crc64 function) and crc16speed.c (crc16 function).
 */

#include "crc16speed.h"
#include "crc64speed.h"
#include "crc_simd.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Test vectors */
static const char *test_string_short = "123456789";
static const char *test_string_lorem =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do "
    "eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut "
    "enim ad minim veniam, quis nostrud exercitation ullamco laboris "
    "nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in "
    "reprehenderit in voluptate velit esse cillum dolore eu fugiat "
    "nulla pariatur. Excepteur sint occaecat cupidatat non proident, "
    "sunt in culpa qui officia deserunt mollit anim id est laborum.";

/* Expected CRC64 values (from reference implementation) */
#define CRC64_123456789 UINT64_C(0xe9c6d914c4b8d9ca)
#define CRC64_LOREM UINT64_C(0xc7794709e69683b3)

/* Expected CRC16 values (from reference implementation) */
#define CRC16_123456789 UINT16_C(0x31c3)
#define CRC16_LOREM UINT16_C(0x4b20)

typedef struct {
    const char *name;
    int passed;
    int failed;
} test_results_t;

static void print_test_header(const char *name) {
    printf("\n=== %s ===\n", name);
}

static void check_result(test_results_t *results, const char *test_name,
                         uint64_t expected, uint64_t actual, int width) {
    bool pass = (expected == actual);
    if (pass) {
        results->passed++;
        printf("[PASS] %s: ", test_name);
    } else {
        results->failed++;
        printf("[FAIL] %s: ", test_name);
    }

    if (width == 16) {
        printf("expected=0x%04x, got=0x%04x\n", (unsigned)expected,
               (unsigned)actual);
    } else {
        printf("expected=0x%016llx, got=0x%016llx\n",
               (unsigned long long)expected, (unsigned long long)actual);
    }
}

/* Test CRC64 implementations */
static void test_crc64(test_results_t *results) {
    print_test_header("CRC64 Tests");

    /* Initialize lookup tables */
    crc64speed_init();
    crc64_simd_init();

    /* Test "123456789" */
    uint64_t ref = crc64(0, test_string_short, 9);
    uint64_t lookup = crc64_lookup(0, test_string_short, 9);
    uint64_t speed = crc64speed(0, test_string_short, 9);
    uint64_t simd = crc64_simd(0, test_string_short, 9);

    check_result(results, "crc64('123456789')", CRC64_123456789, ref, 64);
    check_result(results, "crc64_lookup('123456789')", CRC64_123456789, lookup,
                 64);
    check_result(results, "crc64speed('123456789')", CRC64_123456789, speed,
                 64);
    check_result(results, "crc64_simd('123456789')", CRC64_123456789, simd, 64);

    /* Test Lorem Ipsum (446 bytes including null terminator) */
    size_t lorem_len = strlen(test_string_lorem) + 1;
    ref = crc64(0, test_string_lorem, lorem_len);
    lookup = crc64_lookup(0, test_string_lorem, lorem_len);
    speed = crc64speed(0, test_string_lorem, lorem_len);
    simd = crc64_simd(0, test_string_lorem, lorem_len);

    check_result(results, "crc64(lorem)", CRC64_LOREM, ref, 64);
    check_result(results, "crc64_lookup(lorem)", CRC64_LOREM, lookup, 64);
    check_result(results, "crc64speed(lorem)", CRC64_LOREM, speed, 64);
    check_result(results, "crc64_simd(lorem)", CRC64_LOREM, simd, 64);

    /* Test various sizes to exercise alignment and edge cases */
    printf("\nAlignment and size tests:\n");
    uint8_t *buffer = malloc(4096 + 64);
    if (!buffer) {
        printf("Memory allocation failed!\n");
        return;
    }

    /* Fill with pseudo-random data */
    srand(12345);
    for (int i = 0; i < 4096 + 64; i++) {
        buffer[i] = rand() & 0xff;
    }

    /* Test different sizes */
    size_t sizes[] = {1,   7,    8,    15,   16,   17,  31,  32,
                      33,  63,   64,   65,   127,  128, 129, 255,
                      256, 1000, 1024, 4096, 4097, 0}; /* 0 = sentinel */

    for (int i = 0; sizes[i] != 0; i++) {
        size_t sz = sizes[i];
        ref = crc64(0, buffer, sz);
        speed = crc64speed(0, buffer, sz);
        simd = crc64_simd(0, buffer, sz);

        char name[64];
        snprintf(name, sizeof(name), "crc64speed(size=%zu)", sz);
        check_result(results, name, ref, speed, 64);

        snprintf(name, sizeof(name), "crc64_simd(size=%zu)", sz);
        check_result(results, name, ref, simd, 64);
    }

    /* Test unaligned access */
    printf("\nUnaligned access tests:\n");
    for (int offset = 1; offset < 8; offset++) {
        ref = crc64(0, buffer + offset, 256);
        speed = crc64speed(0, buffer + offset, 256);
        simd = crc64_simd(0, buffer + offset, 256);

        char name[64];
        snprintf(name, sizeof(name), "crc64speed(offset=%d)", offset);
        check_result(results, name, ref, speed, 64);

        snprintf(name, sizeof(name), "crc64_simd(offset=%d)", offset);
        check_result(results, name, ref, simd, 64);
    }

    free(buffer);
}

/* Test CRC16 implementations */
static void test_crc16(test_results_t *results) {
    print_test_header("CRC16 Tests");

    /* Initialize lookup tables */
    crc16speed_init();
    crc16_simd_init();

    /* Test "123456789" */
    uint16_t ref = crc16(0, test_string_short, 9);
    uint16_t lookup = crc16_lookup(0, test_string_short, 9);
    uint16_t speed = crc16speed(0, test_string_short, 9);
    uint16_t simd = crc16_simd(0, test_string_short, 9);

    check_result(results, "crc16('123456789')", CRC16_123456789, ref, 16);
    check_result(results, "crc16_lookup('123456789')", CRC16_123456789, lookup,
                 16);
    check_result(results, "crc16speed('123456789')", CRC16_123456789, speed,
                 16);
    check_result(results, "crc16_simd('123456789')", CRC16_123456789, simd, 16);

    /* Test Lorem Ipsum */
    size_t lorem_len = strlen(test_string_lorem) + 1;
    ref = crc16(0, test_string_lorem, lorem_len);
    lookup = crc16_lookup(0, test_string_lorem, lorem_len);
    speed = crc16speed(0, test_string_lorem, lorem_len);
    simd = crc16_simd(0, test_string_lorem, lorem_len);

    check_result(results, "crc16(lorem)", CRC16_LOREM, ref, 16);
    check_result(results, "crc16_lookup(lorem)", CRC16_LOREM, lookup, 16);
    check_result(results, "crc16speed(lorem)", CRC16_LOREM, speed, 16);
    check_result(results, "crc16_simd(lorem)", CRC16_LOREM, simd, 16);

    /* Additional size tests for CRC16 SIMD boundary conditions */
    printf("\nCRC16 alignment and size tests:\n");
    uint8_t *buffer = malloc(4096 + 64);
    if (!buffer) {
        printf("Memory allocation failed!\n");
        return;
    }

    /* Fill with pseudo-random data */
    srand(54321);
    for (int i = 0; i < 4096 + 64; i++) {
        buffer[i] = rand() & 0xff;
    }

    /* Test critical sizes around SIMD thresholds (64, 128, 256 bytes) */
    size_t sizes[] = {1,   15,  16,  17,   31,   32,   33,   63,
                      64,  65,  127, 128,  129,  255,  256,  257,
                      511, 512, 513, 1000, 1024, 2048, 4096, 0};

    for (int i = 0; sizes[i] != 0; i++) {
        size_t sz = sizes[i];
        ref = crc16(0, buffer, sz);
        speed = crc16speed(0, buffer, sz);
        simd = crc16_simd(0, buffer, sz);

        char name[64];
        snprintf(name, sizeof(name), "crc16speed(size=%zu)", sz);
        check_result(results, name, ref, speed, 16);

        snprintf(name, sizeof(name), "crc16_simd(size=%zu)", sz);
        check_result(results, name, ref, simd, 16);
    }

    /* Test unaligned access */
    printf("\nCRC16 unaligned access tests:\n");
    for (int offset = 1; offset < 8; offset++) {
        ref = crc16(0, buffer + offset, 256);
        speed = crc16speed(0, buffer + offset, 256);
        simd = crc16_simd(0, buffer + offset, 256);

        char name[64];
        snprintf(name, sizeof(name), "crc16speed(offset=%d)", offset);
        check_result(results, name, ref, speed, 16);

        snprintf(name, sizeof(name), "crc16_simd(offset=%d)", offset);
        check_result(results, name, ref, simd, 16);
    }

    /* Test with non-zero initial CRC */
    printf("\nCRC16 non-zero initial CRC tests:\n");
    uint16_t init_crcs[] = {0x0001, 0x1234, 0xFFFF, 0};
    for (int i = 0; init_crcs[i] != 0; i++) {
        uint16_t init = init_crcs[i];
        ref = crc16(init, buffer, 256);
        speed = crc16speed(init, buffer, 256);
        simd = crc16_simd(init, buffer, 256);

        char name[64];
        snprintf(name, sizeof(name), "crc16speed(init=0x%04x)", init);
        check_result(results, name, ref, speed, 16);

        snprintf(name, sizeof(name), "crc16_simd(init=0x%04x)", init);
        check_result(results, name, ref, simd, 16);
    }

    free(buffer);
}

/* Consistency test: compare all implementations against each other */
static void test_consistency(test_results_t *results) {
    print_test_header("Consistency Tests");

    /* Initialize lookup tables */
    crc64speed_init();
    crc16speed_init();
    crc64_simd_init();
    crc16_simd_init();

    /* Generate random data and verify all implementations match */
    srand(time(NULL));
    uint8_t *buffer = malloc(1024 * 1024); /* 1MB */
    if (!buffer) {
        printf("Memory allocation failed!\n");
        return;
    }

    for (int i = 0; i < 1024 * 1024; i++) {
        buffer[i] = rand() & 0xff;
    }

    /* Test at various sizes */
    size_t sizes[] = {100, 1000, 10000, 100000, 1000000, 0};

    for (int i = 0; sizes[i] != 0; i++) {
        size_t sz = sizes[i];

        /* CRC64 */
        uint64_t ref64 = crc64(0, buffer, sz);
        uint64_t speed64 = crc64speed(0, buffer, sz);
        uint64_t simd64 = crc64_simd(0, buffer, sz);

        char name[64];
        snprintf(name, sizeof(name), "crc64 consistency (size=%zu)", sz);
        if (ref64 == speed64 && ref64 == simd64) {
            results->passed++;
            printf("[PASS] %s\n", name);
        } else {
            results->failed++;
            printf(
                "[FAIL] %s: ref=0x%016llx, speed=0x%016llx, simd=0x%016llx\n",
                name, (unsigned long long)ref64, (unsigned long long)speed64,
                (unsigned long long)simd64);
        }

        /* CRC16 */
        uint16_t ref16 = crc16(0, buffer, sz);
        uint16_t speed16 = crc16speed(0, buffer, sz);
        uint16_t simd16 = crc16_simd(0, buffer, sz);

        snprintf(name, sizeof(name), "crc16 consistency (size=%zu)", sz);
        if (ref16 == speed16 && ref16 == simd16) {
            results->passed++;
            printf("[PASS] %s\n", name);
        } else {
            results->failed++;
            printf("[FAIL] %s: ref=0x%04x, speed=0x%04x, simd=0x%04x\n", name,
                   ref16, speed16, simd16);
        }
    }

    free(buffer);
}

static void print_usage(const char *prog) {
    printf("Usage: %s [TEST_GROUP]\n\n", prog);
    printf("TEST_GROUP can be one of:\n");
    printf("  all           Run all tests (default)\n");
    printf("  crc64         CRC64 basic tests\n");
    printf("  crc64_sizes   CRC64 size/alignment tests\n");
    printf("  crc64_align   CRC64 unaligned access tests\n");
    printf("  crc16         CRC16 basic tests\n");
    printf("  crc16_sizes   CRC16 size/alignment tests\n");
    printf("  crc16_align   CRC16 unaligned access tests\n");
    printf("  crc16_init    CRC16 non-zero initial CRC tests\n");
    printf("  consistency   Cross-implementation consistency tests\n");
    printf("  vectors       Known test vector verification\n");
    printf("  simd          SIMD-specific tests (all sizes)\n");
}

/* Test CRC64 basic vectors only */
static void test_crc64_vectors(test_results_t *results) {
    crc64speed_init();
    crc64_simd_init();

    uint64_t ref = crc64(0, test_string_short, 9);
    uint64_t lookup = crc64_lookup(0, test_string_short, 9);
    uint64_t speed = crc64speed(0, test_string_short, 9);
    uint64_t simd = crc64_simd(0, test_string_short, 9);

    check_result(results, "crc64('123456789')", CRC64_123456789, ref, 64);
    check_result(results, "crc64_lookup('123456789')", CRC64_123456789, lookup,
                 64);
    check_result(results, "crc64speed('123456789')", CRC64_123456789, speed,
                 64);
    check_result(results, "crc64_simd('123456789')", CRC64_123456789, simd, 64);

    size_t lorem_len = strlen(test_string_lorem) + 1;
    ref = crc64(0, test_string_lorem, lorem_len);
    lookup = crc64_lookup(0, test_string_lorem, lorem_len);
    speed = crc64speed(0, test_string_lorem, lorem_len);
    simd = crc64_simd(0, test_string_lorem, lorem_len);

    check_result(results, "crc64(lorem)", CRC64_LOREM, ref, 64);
    check_result(results, "crc64_lookup(lorem)", CRC64_LOREM, lookup, 64);
    check_result(results, "crc64speed(lorem)", CRC64_LOREM, speed, 64);
    check_result(results, "crc64_simd(lorem)", CRC64_LOREM, simd, 64);
}

/* Test CRC64 various sizes */
static void test_crc64_sizes(test_results_t *results) {
    crc64speed_init();
    crc64_simd_init();

    uint8_t *buffer = malloc(4096 + 64);
    if (!buffer) {
        printf("Memory allocation failed!\n");
        return;
    }

    srand(12345);
    for (int i = 0; i < 4096 + 64; i++) {
        buffer[i] = rand() & 0xff;
    }

    size_t sizes[] = {1,  7,   8,   15,  16,  17,  31,   32,   33,   63,   64,
                      65, 127, 128, 129, 255, 256, 1000, 1024, 4096, 4097, 0};

    for (int i = 0; sizes[i] != 0; i++) {
        size_t sz = sizes[i];
        uint64_t ref = crc64(0, buffer, sz);
        uint64_t speed = crc64speed(0, buffer, sz);
        uint64_t simd = crc64_simd(0, buffer, sz);

        char name[64];
        snprintf(name, sizeof(name), "crc64speed(size=%zu)", sz);
        check_result(results, name, ref, speed, 64);

        snprintf(name, sizeof(name), "crc64_simd(size=%zu)", sz);
        check_result(results, name, ref, simd, 64);
    }

    free(buffer);
}

/* Test CRC64 unaligned access */
static void test_crc64_align(test_results_t *results) {
    crc64speed_init();
    crc64_simd_init();

    uint8_t *buffer = malloc(4096 + 64);
    if (!buffer) {
        printf("Memory allocation failed!\n");
        return;
    }

    srand(12345);
    for (int i = 0; i < 4096 + 64; i++) {
        buffer[i] = rand() & 0xff;
    }

    for (int offset = 1; offset < 8; offset++) {
        uint64_t ref = crc64(0, buffer + offset, 256);
        uint64_t speed = crc64speed(0, buffer + offset, 256);
        uint64_t simd = crc64_simd(0, buffer + offset, 256);

        char name[64];
        snprintf(name, sizeof(name), "crc64speed(offset=%d)", offset);
        check_result(results, name, ref, speed, 64);

        snprintf(name, sizeof(name), "crc64_simd(offset=%d)", offset);
        check_result(results, name, ref, simd, 64);
    }

    free(buffer);
}

/* Test CRC16 basic vectors only */
static void test_crc16_vectors(test_results_t *results) {
    crc16speed_init();
    crc16_simd_init();

    uint16_t ref = crc16(0, test_string_short, 9);
    uint16_t lookup = crc16_lookup(0, test_string_short, 9);
    uint16_t speed = crc16speed(0, test_string_short, 9);
    uint16_t simd = crc16_simd(0, test_string_short, 9);

    check_result(results, "crc16('123456789')", CRC16_123456789, ref, 16);
    check_result(results, "crc16_lookup('123456789')", CRC16_123456789, lookup,
                 16);
    check_result(results, "crc16speed('123456789')", CRC16_123456789, speed,
                 16);
    check_result(results, "crc16_simd('123456789')", CRC16_123456789, simd, 16);

    size_t lorem_len = strlen(test_string_lorem) + 1;
    ref = crc16(0, test_string_lorem, lorem_len);
    lookup = crc16_lookup(0, test_string_lorem, lorem_len);
    speed = crc16speed(0, test_string_lorem, lorem_len);
    simd = crc16_simd(0, test_string_lorem, lorem_len);

    check_result(results, "crc16(lorem)", CRC16_LOREM, ref, 16);
    check_result(results, "crc16_lookup(lorem)", CRC16_LOREM, lookup, 16);
    check_result(results, "crc16speed(lorem)", CRC16_LOREM, speed, 16);
    check_result(results, "crc16_simd(lorem)", CRC16_LOREM, simd, 16);
}

/* Test CRC16 various sizes */
static void test_crc16_sizes(test_results_t *results) {
    crc16speed_init();
    crc16_simd_init();

    uint8_t *buffer = malloc(4096 + 64);
    if (!buffer) {
        printf("Memory allocation failed!\n");
        return;
    }

    srand(54321);
    for (int i = 0; i < 4096 + 64; i++) {
        buffer[i] = rand() & 0xff;
    }

    size_t sizes[] = {1,   15,  16,  17,   31,   32,   33,   63,
                      64,  65,  127, 128,  129,  255,  256,  257,
                      511, 512, 513, 1000, 1024, 2048, 4096, 0};

    for (int i = 0; sizes[i] != 0; i++) {
        size_t sz = sizes[i];
        uint16_t ref = crc16(0, buffer, sz);
        uint16_t speed = crc16speed(0, buffer, sz);
        uint16_t simd = crc16_simd(0, buffer, sz);

        char name[64];
        snprintf(name, sizeof(name), "crc16speed(size=%zu)", sz);
        check_result(results, name, ref, speed, 16);

        snprintf(name, sizeof(name), "crc16_simd(size=%zu)", sz);
        check_result(results, name, ref, simd, 16);
    }

    free(buffer);
}

/* Test CRC16 unaligned access */
static void test_crc16_align(test_results_t *results) {
    crc16speed_init();
    crc16_simd_init();

    uint8_t *buffer = malloc(4096 + 64);
    if (!buffer) {
        printf("Memory allocation failed!\n");
        return;
    }

    srand(54321);
    for (int i = 0; i < 4096 + 64; i++) {
        buffer[i] = rand() & 0xff;
    }

    for (int offset = 1; offset < 8; offset++) {
        uint16_t ref = crc16(0, buffer + offset, 256);
        uint16_t speed = crc16speed(0, buffer + offset, 256);
        uint16_t simd = crc16_simd(0, buffer + offset, 256);

        char name[64];
        snprintf(name, sizeof(name), "crc16speed(offset=%d)", offset);
        check_result(results, name, ref, speed, 16);

        snprintf(name, sizeof(name), "crc16_simd(offset=%d)", offset);
        check_result(results, name, ref, simd, 16);
    }

    free(buffer);
}

/* Test CRC16 with non-zero initial CRC */
static void test_crc16_init(test_results_t *results) {
    crc16speed_init();
    crc16_simd_init();

    uint8_t *buffer = malloc(4096 + 64);
    if (!buffer) {
        printf("Memory allocation failed!\n");
        return;
    }

    srand(54321);
    for (int i = 0; i < 4096 + 64; i++) {
        buffer[i] = rand() & 0xff;
    }

    uint16_t init_crcs[] = {0x0001, 0x1234, 0xFFFF, 0};
    for (int i = 0; init_crcs[i] != 0; i++) {
        uint16_t init = init_crcs[i];
        uint16_t ref = crc16(init, buffer, 256);
        uint16_t speed = crc16speed(init, buffer, 256);
        uint16_t simd = crc16_simd(init, buffer, 256);

        char name[64];
        snprintf(name, sizeof(name), "crc16speed(init=0x%04x)", init);
        check_result(results, name, ref, speed, 16);

        snprintf(name, sizeof(name), "crc16_simd(init=0x%04x)", init);
        check_result(results, name, ref, simd, 16);
    }

    free(buffer);
}

/* Test known vectors for all implementations */
static void test_vectors(test_results_t *results) {
    test_crc64_vectors(results);
    test_crc16_vectors(results);
}

/* SIMD-specific tests (comprehensive size testing) */
static void test_simd(test_results_t *results) {
    test_crc64_sizes(results);
    test_crc64_align(results);
    test_crc16_sizes(results);
    test_crc16_align(results);
    test_crc16_init(results);
}

int main(int argc, char *argv[]) {
    const char *test_group = (argc > 1) ? argv[1] : "all";

    if (strcmp(test_group, "-h") == 0 || strcmp(test_group, "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }

    printf("CRC Test Suite\n");
    printf("==============\n");
    printf("SIMD support: %s\n", crc_simd_available() ? "YES" : "NO");
    printf("Test group: %s\n", test_group);

    test_results_t results = {.name = test_group, .passed = 0, .failed = 0};

    if (strcmp(test_group, "all") == 0) {
        test_crc64(&results);
        test_crc16(&results);
        test_consistency(&results);
    } else if (strcmp(test_group, "crc64") == 0) {
        test_crc64_vectors(&results);
    } else if (strcmp(test_group, "crc64_sizes") == 0) {
        test_crc64_sizes(&results);
    } else if (strcmp(test_group, "crc64_align") == 0) {
        test_crc64_align(&results);
    } else if (strcmp(test_group, "crc16") == 0) {
        test_crc16_vectors(&results);
    } else if (strcmp(test_group, "crc16_sizes") == 0) {
        test_crc16_sizes(&results);
    } else if (strcmp(test_group, "crc16_align") == 0) {
        test_crc16_align(&results);
    } else if (strcmp(test_group, "crc16_init") == 0) {
        test_crc16_init(&results);
    } else if (strcmp(test_group, "consistency") == 0) {
        test_consistency(&results);
    } else if (strcmp(test_group, "vectors") == 0) {
        test_vectors(&results);
    } else if (strcmp(test_group, "simd") == 0) {
        test_simd(&results);
    } else {
        fprintf(stderr, "Unknown test group: %s\n", test_group);
        print_usage(argv[0]);
        return 1;
    }

    printf("\n========================================\n");
    printf("RESULTS [%s]: %d passed, %d failed\n", test_group, results.passed,
           results.failed);
    printf("========================================\n");

    return results.failed > 0 ? 1 : 0;
}
