/* crcspeed - CRC Performance Evaluation and Verification Tool
 *
 * This tool provides:
 * - Verification of all CRC implementations against known test vectors
 * - Performance benchmarking with accurate timing and statistics
 * - File analysis comparing all implementations
 * - Quick file hashing with the fastest available method
 * - Cross-platform SIMD detection and utilization
 *
 * Copyright (c) 2014, Matt Stancliff <matt@genges.com>
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "crc16speed.h"
#include "crc64speed.h"
#include "crc_simd.h"
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

/* Version info */
#define CRCSPEED_VERSION "2.1.0"

/* Default benchmark parameters */
#define DEFAULT_ITERATIONS 10
#define DEFAULT_BUFFER_SIZE (1024 * 1024) /* 1 MB */
#define WARMUP_ITERATIONS 2

/* Terminal colors (ANSI escape codes) */
#define COLOR_RESET "\033[0m"
#define COLOR_GREEN "\033[32m"
#define COLOR_RED "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_CYAN "\033[36m"
#define COLOR_BOLD "\033[1m"
#define COLOR_DIM "\033[2m"

/* Check if stdout is a terminal for color support */
static bool use_colors = false;

static void init_colors(void) {
    use_colors = isatty(STDOUT_FILENO);
}

#define PASS_STR (use_colors ? COLOR_GREEN "PASS" COLOR_RESET : "PASS")
#define FAIL_STR (use_colors ? COLOR_RED "FAIL" COLOR_RESET : "FAIL")
#define WARN_STR (use_colors ? COLOR_YELLOW "WARN" COLOR_RESET : "WARN")
#define BOLD(s) (use_colors ? COLOR_BOLD s COLOR_RESET : s)
#define DIM(s) (use_colors ? COLOR_DIM s COLOR_RESET : s)

/* High-resolution timer */
static long long ustime(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((long long)tv.tv_sec) * 1000000LL + tv.tv_usec;
}

/* CPU cycle counter for accurate per-byte measurements */
#if defined(__aarch64__)
static inline uint64_t rdtsc(void) {
    uint64_t val;
    __sync_synchronize();
    asm volatile("mrs %0, cntvct_el0" : "=r"(val));
    return val;
}
static inline uint64_t get_freq(void) {
    uint64_t freq;
    asm volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    return freq;
}
#elif defined(__x86_64__) || defined(_M_X64)
static inline uint64_t rdtsc(void) {
    unsigned int lo, hi;
    __sync_synchronize();
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
__attribute__((unused)) static inline uint64_t get_freq(void) {
    return 0; /* x86 doesn't have a standard frequency register */
}
#else
static inline uint64_t rdtsc(void) {
    return 0;
}
__attribute__((unused)) static inline uint64_t get_freq(void) {
    return 0;
}
#endif

/* Test vector structure */
typedef struct {
    const char *name;
    const void *data;
    size_t len;
    uint64_t expected_crc64;
    uint16_t expected_crc16;
} test_vector_t;

/* Standard test vectors */
static const char test_123456789[] = "123456789";
static const char test_lorem[] =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do "
    "eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut "
    "enim ad minim veniam, quis nostrud exercitation ullamco laboris "
    "nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in "
    "reprehenderit in voluptate velit esse cillum dolore eu fugiat "
    "nulla pariatur. Excepteur sint occaecat cupidatat non proident, "
    "sunt in culpa qui officia deserunt mollit anim id est laborum.";

static const test_vector_t test_vectors[] = {
    {"123456789", test_123456789, 9, UINT64_C(0xe9c6d914c4b8d9ca), 0x31c3},
    {"Lorem ipsum (446 bytes)", test_lorem, sizeof(test_lorem),
     UINT64_C(0xc7794709e69683b3), 0x4b20},
    {NULL, NULL, 0, 0, 0} /* sentinel */
};

/* CRC function types */
typedef uint64_t (*crc64_fn)(uint64_t, const void *, uint64_t);
typedef uint16_t (*crc16_fn)(uint16_t, const void *, uint64_t);

/* Implementation descriptor */
typedef struct {
    const char *name;
    const char *short_name;
    const char *description;
    void *fn;
    bool is_crc16;
    bool is_simd;
} impl_t;

static const impl_t implementations[] = {
    {"crc64", "64bit", "Bit-by-bit reference", (void *)crc64, false, false},
    {"crc64_lookup", "64look", "Single-byte table lookup", (void *)crc64_lookup,
     false, false},
    {"crc64speed", "64speed", "Slice-by-8 table lookup", (void *)crc64speed,
     false, false},
    {"crc64_simd", "64simd", "PCLMULQDQ/PMULL SIMD", (void *)crc64_simd, false,
     true},
    {"crc16", "16bit", "Bit-by-bit reference", (void *)crc16, true, false},
    {"crc16_lookup", "16look", "Single-byte table lookup", (void *)crc16_lookup,
     true, false},
    {"crc16speed", "16speed", "Slice-by-8 table lookup", (void *)crc16speed,
     true, false},
    {"crc16_simd", "16simd", "PCLMULQDQ/PMULL SIMD", (void *)crc16_simd, true,
     true},
    {NULL, NULL, NULL, NULL, false, false} /* sentinel */
};

/* Print usage information */
static void print_usage(const char *prog) {
    printf("%scrcspeed v%s%s - CRC Performance Evaluation Tool\n\n",
           use_colors ? COLOR_BOLD : "", CRCSPEED_VERSION,
           use_colors ? COLOR_RESET : "");
    printf("Usage: %s [OPTIONS] [FILE...]\n\n", prog);

    printf("%sModes:%s\n", use_colors ? COLOR_BOLD : "",
           use_colors ? COLOR_RESET : "");
    printf("  (default)         Run verification tests and performance "
           "benchmarks\n");
    printf("  FILE...           Analyze file(s) with ALL implementations "
           "(compare/validate)\n");
    printf("  --hash FILE...    Quick hash file(s) with fastest algorithm\n");
    printf("\n");

    printf("%sOptions:%s\n", use_colors ? COLOR_BOLD : "",
           use_colors ? COLOR_RESET : "");
    printf("  -s, --size SIZE   Buffer size for benchmarks (default: 1MB)\n");
    printf("                    Supports suffixes: K, M, G (e.g., 4M, 256K)\n");
    printf("  -n, --iterations N  Benchmark iterations (default: 10)\n");
    printf("  -a, --algorithm ALG Algorithm for --hash mode\n");
    printf("  -q, --quiet       Minimal output (for scripting)\n");
    printf("  -c, --no-color    Disable colored output\n");
    printf("  -h, --help        Show this help message\n");
    printf("\n");

    printf("%sAvailable Algorithms:%s\n", use_colors ? COLOR_BOLD : "",
           use_colors ? COLOR_RESET : "");
    printf("  %-16s  %-28s  %s\n", "Name", "Description", "Type");
    printf("  %-16s  %-28s  %s\n", "----", "-----------", "----");
    for (const impl_t *impl = implementations; impl->name; impl++) {
        printf("  %-16s  %-28s  %s\n", impl->name, impl->description,
               impl->is_simd ? "[SIMD]" : "");
    }
    printf("\n");

    printf("%sExamples:%s\n", use_colors ? COLOR_BOLD : "",
           use_colors ? COLOR_RESET : "");
    printf("  %s                      # Run full benchmark suite\n", prog);
    printf("  %s -s 4M -n 1000        # Benchmark with 4MB buffer\n", prog);
    printf("  %s myfile.bin           # Compare all CRCs for file\n", prog);
    printf("  %s --hash *.bin         # Quick hash files\n", prog);
    printf("  %s --hash -a crc16_simd file.bin  # Hash with specific algo\n",
           prog);
}

/* Parse size with optional suffix (K, M, G) */
static size_t parse_size(const char *str) {
    char *endptr;
    double val = strtod(str, &endptr);
    if (endptr == str) {
        fprintf(stderr, "Invalid size: %s\n", str);
        exit(1);
    }
    switch (*endptr) {
    case 'G':
    case 'g':
        val *= 1024; /* fallthrough */
    case 'M':
    case 'm':
        val *= 1024; /* fallthrough */
    case 'K':
    case 'k':
        val *= 1024;
        break;
    case '\0':
        break;
    default:
        fprintf(stderr, "Invalid size suffix: %c\n", *endptr);
        exit(1);
    }
    return (size_t)val;
}

/* Format bytes as human-readable */
static const char *format_size(size_t bytes, char *buf, size_t buflen) {
    if (bytes >= 1024 * 1024 * 1024) {
        snprintf(buf, buflen, "%.2f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    } else if (bytes >= 1024 * 1024) {
        snprintf(buf, buflen, "%.2f MB", bytes / (1024.0 * 1024.0));
    } else if (bytes >= 1024) {
        snprintf(buf, buflen, "%.2f KB", bytes / 1024.0);
    } else {
        snprintf(buf, buflen, "%zu B", bytes);
    }
    return buf;
}

/* Format throughput */
static const char *format_throughput(double mbs, char *buf, size_t buflen) {
    if (mbs >= 1000) {
        snprintf(buf, buflen, "%.2f GB/s", mbs / 1024.0);
    } else {
        snprintf(buf, buflen, "%.2f MB/s", mbs);
    }
    return buf;
}

/* Print system information */
static void print_system_info(void) {
    printf("\n%sSystem Information%s\n", BOLD(""), "");
    printf("══════════════════\n");
#if defined(__aarch64__)
    printf("  Architecture:  ARM64 (AArch64)\n");
    printf("  SIMD Engine:   NEON + PMULL (crypto extension)\n");
    uint64_t freq = get_freq();
    if (freq > 0) {
        printf("  Timer Freq:    %.2f MHz\n", freq / 1e6);
    }
#elif defined(__x86_64__) || defined(_M_X64)
    printf("  Architecture:  x86-64\n");
    printf("  SIMD Engine:   SSE4.1 + PCLMULQDQ\n");
#else
    printf("  Architecture:  Unknown\n");
#endif
    printf("  SIMD Available: %s\n",
           crc_simd_available()
               ? (use_colors ? COLOR_GREEN "YES" COLOR_RESET : "YES")
               : (use_colors ? COLOR_RED "NO" COLOR_RESET : "NO"));
}

/* Print a separator bar */
static void print_separator(const char *title) {
    printf("\n%s%s%s\n", BOLD(""), title, "");
    for (size_t i = 0; i < strlen(title); i++) {
        printf("═");
    }
    printf("\n");
}

/* Run verification tests */
static int run_verification(void) {
    int passed = 0, failed = 0, skipped = 0;

    print_separator("Verification Tests");
    printf("Testing all implementations against known test vectors...\n\n");

    /* Test each implementation against all test vectors */
    for (const impl_t *impl = implementations; impl->name; impl++) {
        if (impl->is_simd && !crc_simd_available()) {
            skipped++;
            continue;
        }

        bool impl_ok = true;
        for (const test_vector_t *tv = test_vectors; tv->name; tv++) {
            uint64_t result;
            uint64_t expected;

            if (impl->is_crc16) {
                crc16_fn fn = (crc16_fn)impl->fn;
                result = fn(0, tv->data, tv->len);
                expected = tv->expected_crc16;
            } else {
                crc64_fn fn = (crc64_fn)impl->fn;
                result = fn(0, tv->data, tv->len);
                expected = tv->expected_crc64;
            }

            if (result != expected) {
                impl_ok = false;
                failed++;
                printf("  [%s] %-14s %-20s: ", FAIL_STR, impl->name, tv->name);
                if (impl->is_crc16) {
                    printf("0x%04" PRIx64 " != 0x%04" PRIx64 "\n", result,
                           expected);
                } else {
                    printf("0x%016" PRIx64 " != 0x%016" PRIx64 "\n", result,
                           expected);
                }
            } else {
                passed++;
            }
        }

        if (impl_ok) {
            printf("  [%s] %-14s All test vectors passed\n", PASS_STR,
                   impl->name);
        }
    }

    printf("\n  Results: %s%d passed%s", use_colors ? COLOR_GREEN : "", passed,
           use_colors ? COLOR_RESET : "");
    if (failed > 0) {
        printf(", %s%d failed%s", use_colors ? COLOR_RED : "", failed,
               use_colors ? COLOR_RESET : "");
    }
    if (skipped > 0) {
        printf(", %s%d skipped%s", use_colors ? COLOR_YELLOW : "", skipped,
               use_colors ? COLOR_RESET : "");
    }
    printf("\n");

    return failed > 0 ? 1 : 0;
}

/* Benchmark result structure */
typedef struct {
    const char *name;
    double throughput_mbs;
    double cycles_per_byte;
    double time_sec;
    uint64_t result;
    bool valid;
} bench_result_t;

/* Run a single benchmark */
static bench_result_t run_single_benchmark(const impl_t *impl, const void *data,
                                           size_t len, int iterations) {
    bench_result_t result = {.name = impl->name, .valid = true};

    /* Warmup */
    for (int i = 0; i < WARMUP_ITERATIONS; i++) {
        if (impl->is_crc16) {
            ((crc16_fn)impl->fn)(0, data, len);
        } else {
            ((crc64_fn)impl->fn)(0, data, len);
        }
    }

    /* Timed runs */
    long long start_time = ustime();
    uint64_t start_cycles = rdtsc();

    for (int i = 0; i < iterations; i++) {
        if (impl->is_crc16) {
            result.result = ((crc16_fn)impl->fn)(0, data, len);
        } else {
            result.result = ((crc64_fn)impl->fn)(0, data, len);
        }
    }

    uint64_t end_cycles = rdtsc();
    long long end_time = ustime();

    result.time_sec = (end_time - start_time) / 1e6;
    size_t total_bytes = len * iterations;

    result.throughput_mbs = (total_bytes / (1024.0 * 1024.0)) / result.time_sec;
    result.cycles_per_byte = (double)(end_cycles - start_cycles) / total_bytes;

    return result;
}

/* Run benchmarks */
static int run_benchmarks(size_t buffer_size, int iterations) {
    char size_buf[32];

    print_separator("Performance Benchmarks");

    printf("  Buffer Size:   %s\n",
           format_size(buffer_size, size_buf, sizeof(size_buf)));
    printf("  Iterations:    %d\n", iterations);
    printf("  Warmup:        %d iterations\n", WARMUP_ITERATIONS);
    printf("  Total Data:    %s per algorithm\n",
           format_size(buffer_size * iterations, size_buf, sizeof(size_buf)));

    /* Allocate and fill test buffer */
    uint8_t *buffer = malloc(buffer_size);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate %zu bytes\n", buffer_size);
        return 1;
    }

    /* Fill with pseudo-random data */
    srand(12345);
    for (size_t i = 0; i < buffer_size; i++) {
        buffer[i] = rand() & 0xff;
    }

    /* Cache the lookup tables */
    crc64speed_cache_table();
    crc16speed_cache_table();

    /* Run CRC64 benchmarks */
    printf("\n  %sCRC64 Results:%s\n", BOLD(""), "");
    printf("  %-14s  %12s  %10s  %10s  %s\n", "Algorithm", "MB/s", "GB/s",
           "Cycles/B", "Status");
    printf("  %-14s  %12s  %10s  %10s  %s\n", "──────────────", "────────────",
           "──────────", "──────────", "──────");

    uint64_t crc64_ref = 0;
    bench_result_t crc64_speed_result = {0}, crc64_simd_result = {0};

    for (const impl_t *impl = implementations; impl->name; impl++) {
        if (impl->is_crc16) {
            continue;
        }
        if (impl->is_simd && !crc_simd_available()) {
            continue;
        }

        bench_result_t r =
            run_single_benchmark(impl, buffer, buffer_size, iterations);

        bool match = (crc64_ref == 0 || r.result == crc64_ref);
        if (crc64_ref == 0) {
            crc64_ref = r.result;
        }

        const char *status = match ? PASS_STR : FAIL_STR;
        double gbs = r.throughput_mbs / 1024.0;

        printf("  %-14s  %12.2f  %10.2f  %10.3f  [%s]\n", impl->name,
               r.throughput_mbs, gbs, r.cycles_per_byte, status);

        if (strcmp(impl->name, "crc64speed") == 0) {
            crc64_speed_result = r;
        }
        if (strcmp(impl->name, "crc64_simd") == 0) {
            crc64_simd_result = r;
        }
    }

    /* Run CRC16 benchmarks */
    printf("\n  %sCRC16 Results:%s\n", BOLD(""), "");
    printf("  %-14s  %12s  %10s  %10s  %s\n", "Algorithm", "MB/s", "GB/s",
           "Cycles/B", "Status");
    printf("  %-14s  %12s  %10s  %10s  %s\n", "──────────────", "────────────",
           "──────────", "──────────", "──────");

    uint16_t crc16_ref = 0;
    bench_result_t crc16_speed_result = {0}, crc16_simd_result = {0};

    for (const impl_t *impl = implementations; impl->name; impl++) {
        if (!impl->is_crc16) {
            continue;
        }
        if (impl->is_simd && !crc_simd_available()) {
            continue;
        }

        bench_result_t r =
            run_single_benchmark(impl, buffer, buffer_size, iterations);

        bool match = (crc16_ref == 0 || (r.result & 0xFFFF) == crc16_ref);
        if (crc16_ref == 0) {
            crc16_ref = r.result & 0xFFFF;
        }

        const char *status = match ? PASS_STR : FAIL_STR;
        double gbs = r.throughput_mbs / 1024.0;

        printf("  %-14s  %12.2f  %10.2f  %10.3f  [%s]\n", impl->name,
               r.throughput_mbs, gbs, r.cycles_per_byte, status);

        if (strcmp(impl->name, "crc16speed") == 0) {
            crc16_speed_result = r;
        }
        if (strcmp(impl->name, "crc16_simd") == 0) {
            crc16_simd_result = r;
        }
    }

    /* Performance summary */
    if (crc_simd_available()) {
        printf("\n  %sSpeedup Summary:%s\n", BOLD(""), "");
        if (crc64_speed_result.throughput_mbs > 0 &&
            crc64_simd_result.throughput_mbs > 0) {
            double speedup = crc64_simd_result.throughput_mbs /
                             crc64_speed_result.throughput_mbs;
            printf("  CRC64: SIMD is %s%.1fx%s faster than table lookup\n",
                   use_colors ? COLOR_CYAN : "", speedup,
                   use_colors ? COLOR_RESET : "");
        }
        if (crc16_speed_result.throughput_mbs > 0 &&
            crc16_simd_result.throughput_mbs > 0) {
            double speedup = crc16_simd_result.throughput_mbs /
                             crc16_speed_result.throughput_mbs;
            printf("  CRC16: SIMD is %s%.1fx%s faster than table lookup\n",
                   use_colors ? COLOR_CYAN : "", speedup,
                   use_colors ? COLOR_RESET : "");
        }
    }

    free(buffer);
    return 0;
}

/* Benchmark file with all implementations - THE MAIN USE CASE */
static int benchmark_file(const char *filename, int iterations) {
    char size_buf[32];

    struct stat st;
    if (stat(filename, &st) != 0) {
        fprintf(stderr, "Cannot stat '%s': %s\n", filename, strerror(errno));
        return 1;
    }

    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "'%s' is not a regular file\n", filename);
        return 1;
    }

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Cannot open '%s': %s\n", filename, strerror(errno));
        return 1;
    }

    size_t file_size = st.st_size;
    uint8_t *buffer = malloc(file_size > 0 ? file_size : 1);
    if (!buffer) {
        fprintf(stderr, "Cannot allocate %zu bytes for '%s'\n", file_size,
                filename);
        fclose(fp);
        return 1;
    }

    if (file_size > 0 && fread(buffer, file_size, 1, fp) != 1) {
        fprintf(stderr, "Cannot read '%s': %s\n", filename, strerror(errno));
        free(buffer);
        fclose(fp);
        return 1;
    }
    fclose(fp);

    /* Cache lookup tables */
    crc64speed_cache_table();
    crc16speed_cache_table();

    printf("\n%sBenchmark: %s%s\n", BOLD(""), filename, "");
    printf("═══════════");
    for (size_t i = 0; i < strlen(filename); i++) {
        printf("═");
    }
    printf("\n");
    printf("  File Size:   %s (%zu bytes)\n",
           format_size(file_size, size_buf, sizeof(size_buf)), file_size);
    printf("  Iterations:  %d\n", iterations);
    printf("  Total Data:  %s per algorithm\n\n",
           format_size(file_size * iterations, size_buf, sizeof(size_buf)));

    /* CRC64 benchmarks */
    printf("  %sCRC64 Results:%s\n", BOLD(""), "");
    printf("  %-14s  %-18s  %12s  %10s  %10s  %s\n", "Algorithm", "CRC Value",
           "MB/s", "GB/s", "Cycles/B", "Status");
    printf("  %-14s  %-18s  %12s  %10s  %10s  %s\n", "──────────────",
           "──────────────────", "────────────", "──────────", "──────────",
           "──────");

    uint64_t crc64_ref = 0;
    bool crc64_error = false;
    double crc64_speed_tp = 0, crc64_simd_tp = 0;

    for (const impl_t *impl = implementations; impl->name; impl++) {
        if (impl->is_crc16) {
            continue;
        }
        if (impl->is_simd && !crc_simd_available()) {
            continue;
        }

        crc64_fn fn = (crc64_fn)impl->fn;

        /* Warmup */
        for (int w = 0; w < WARMUP_ITERATIONS; w++) {
            fn(0, buffer, file_size);
        }

        /* Timed runs */
        long long start = ustime();
        uint64_t start_cycles = rdtsc();
        uint64_t result = 0;

        for (int i = 0; i < iterations; i++) {
            result = fn(0, buffer, file_size);
        }

        uint64_t end_cycles = rdtsc();
        long long elapsed = ustime() - start;

        bool match = (crc64_ref == 0 || result == crc64_ref);
        if (crc64_ref == 0) {
            crc64_ref = result;
        }
        if (!match) {
            crc64_error = true;
        }

        size_t total_bytes = file_size * iterations;
        double mbs = (total_bytes / (1024.0 * 1024.0)) / (elapsed / 1e6);
        double gbs = mbs / 1024.0;
        double cycles = (double)(end_cycles - start_cycles) / total_bytes;

        printf("  %-14s  0x%016" PRIx64 "  %12.2f  %10.2f  %10.3f  [%s]\n",
               impl->name, result, mbs, gbs, cycles,
               match ? PASS_STR : FAIL_STR);

        if (strcmp(impl->name, "crc64speed") == 0) {
            crc64_speed_tp = mbs;
        }
        if (strcmp(impl->name, "crc64_simd") == 0) {
            crc64_simd_tp = mbs;
        }
    }

    /* CRC16 benchmarks */
    printf("\n  %sCRC16 Results:%s\n", BOLD(""), "");
    printf("  %-14s  %-18s  %12s  %10s  %10s  %s\n", "Algorithm", "CRC Value",
           "MB/s", "GB/s", "Cycles/B", "Status");
    printf("  %-14s  %-18s  %12s  %10s  %10s  %s\n", "──────────────",
           "──────────────────", "────────────", "──────────", "──────────",
           "──────");

    uint16_t crc16_ref = 0;
    bool crc16_error = false;
    double crc16_speed_tp = 0, crc16_simd_tp = 0;

    for (const impl_t *impl = implementations; impl->name; impl++) {
        if (!impl->is_crc16) {
            continue;
        }
        if (impl->is_simd && !crc_simd_available()) {
            continue;
        }

        crc16_fn fn = (crc16_fn)impl->fn;

        /* Warmup */
        for (int w = 0; w < WARMUP_ITERATIONS; w++) {
            fn(0, buffer, file_size);
        }

        /* Timed runs */
        long long start = ustime();
        uint64_t start_cycles = rdtsc();
        uint16_t result = 0;

        for (int i = 0; i < iterations; i++) {
            result = fn(0, buffer, file_size);
        }

        uint64_t end_cycles = rdtsc();
        long long elapsed = ustime() - start;

        bool match = (crc16_ref == 0 || result == crc16_ref);
        if (crc16_ref == 0) {
            crc16_ref = result;
        }
        if (!match) {
            crc16_error = true;
        }

        size_t total_bytes = file_size * iterations;
        double mbs = (total_bytes / (1024.0 * 1024.0)) / (elapsed / 1e6);
        double gbs = mbs / 1024.0;
        double cycles = (double)(end_cycles - start_cycles) / total_bytes;

        printf("  %-14s  0x%04x              %12.2f  %10.2f  %10.3f  [%s]\n",
               impl->name, result, mbs, gbs, cycles,
               match ? PASS_STR : FAIL_STR);

        if (strcmp(impl->name, "crc16speed") == 0) {
            crc16_speed_tp = mbs;
        }
        if (strcmp(impl->name, "crc16_simd") == 0) {
            crc16_simd_tp = mbs;
        }
    }

    /* Summary */
    printf("\n  %sSummary:%s\n", BOLD(""), "");
    printf("  CRC64: 0x%016" PRIx64 " %s\n", crc64_ref,
           crc64_error ? FAIL_STR : PASS_STR);
    printf("  CRC16: 0x%04x             %s\n", crc16_ref,
           crc16_error ? FAIL_STR : PASS_STR);

    if (crc_simd_available()) {
        printf("\n  %sSpeedup (SIMD vs Table):%s\n", BOLD(""), "");
        if (crc64_speed_tp > 0 && crc64_simd_tp > 0) {
            printf("  CRC64: %s%.1fx%s\n", use_colors ? COLOR_CYAN : "",
                   crc64_simd_tp / crc64_speed_tp,
                   use_colors ? COLOR_RESET : "");
        }
        if (crc16_speed_tp > 0 && crc16_simd_tp > 0) {
            printf("  CRC16: %s%.1fx%s\n", use_colors ? COLOR_CYAN : "",
                   crc16_simd_tp / crc16_speed_tp,
                   use_colors ? COLOR_RESET : "");
        }
    }

    free(buffer);
    return (crc64_error || crc16_error) ? 1 : 0;
}

/* Quick hash file with fastest algorithm */
static int hash_file(const char *filename, const impl_t *impl, bool quiet) {
    struct stat st;
    if (stat(filename, &st) != 0) {
        fprintf(stderr, "Cannot stat '%s': %s\n", filename, strerror(errno));
        return 1;
    }

    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "'%s' is not a regular file\n", filename);
        return 1;
    }

    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Cannot open '%s': %s\n", filename, strerror(errno));
        return 1;
    }

    size_t file_size = st.st_size;
    uint8_t *buffer = malloc(file_size > 0 ? file_size : 1);
    if (!buffer) {
        fprintf(stderr, "Cannot allocate %zu bytes\n", file_size);
        fclose(fp);
        return 1;
    }

    if (file_size > 0 && fread(buffer, file_size, 1, fp) != 1) {
        fprintf(stderr, "Cannot read '%s': %s\n", filename, strerror(errno));
        free(buffer);
        fclose(fp);
        return 1;
    }
    fclose(fp);

    long long start = ustime();
    uint64_t result;

    if (impl->is_crc16) {
        result = ((crc16_fn)impl->fn)(0, buffer, file_size);
    } else {
        result = ((crc64_fn)impl->fn)(0, buffer, file_size);
    }

    long long elapsed = ustime() - start;
    free(buffer);

    if (quiet) {
        if (impl->is_crc16) {
            printf("%04" PRIx64 "  %s\n", result & 0xFFFF, filename);
        } else {
            printf("%016" PRIx64 "  %s\n", result, filename);
        }
    } else {
        char size_buf[32], tp_buf[32];
        double mbs = (file_size / (1024.0 * 1024.0)) / (elapsed / 1e6);

        if (impl->is_crc16) {
            printf("0x%04" PRIx64 "  %s  (%s, %s)\n", result & 0xFFFF, filename,
                   format_size(file_size, size_buf, sizeof(size_buf)),
                   format_throughput(mbs, tp_buf, sizeof(tp_buf)));
        } else {
            printf("0x%016" PRIx64 "  %s  (%s, %s)\n", result, filename,
                   format_size(file_size, size_buf, sizeof(size_buf)),
                   format_throughput(mbs, tp_buf, sizeof(tp_buf)));
        }
    }

    return 0;
}

/* Find implementation by name */
static const impl_t *find_impl(const char *name) {
    for (const impl_t *impl = implementations; impl->name; impl++) {
        if (strcmp(impl->name, name) == 0) {
            return impl;
        }
    }
    return NULL;
}

/* Main entry point */
int main(int argc, char *argv[]) {
    init_colors();

    /* Initialize all CRC implementations */
    crc64speed_init();
    crc16speed_init();
    crc64_simd_init();
    crc16_simd_init();

    /* Command line options */
    static struct option long_options[] = {
        {"size", required_argument, 0, 's'},
        {"iterations", required_argument, 0, 'n'},
        {"algorithm", required_argument, 0, 'a'},
        {"hash", no_argument, 0, 'H'},
        {"quiet", no_argument, 0, 'q'},
        {"no-color", no_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    bool hash_mode = false;
    bool quiet = false;
    size_t buffer_size = DEFAULT_BUFFER_SIZE;
    int iterations = DEFAULT_ITERATIONS;
    const impl_t *selected_impl = NULL;

    int opt;
    while ((opt = getopt_long(argc, argv, "s:n:a:Hqch", long_options, NULL)) !=
           -1) {
        switch (opt) {
        case 's':
            buffer_size = parse_size(optarg);
            break;
        case 'n':
            iterations = atoi(optarg);
            if (iterations < 1) {
                fprintf(stderr, "Invalid iteration count: %s\n", optarg);
                return 1;
            }
            break;
        case 'a':
            selected_impl = find_impl(optarg);
            if (!selected_impl) {
                fprintf(stderr, "Unknown algorithm: %s\n", optarg);
                fprintf(stderr, "Use --help to see available algorithms\n");
                return 1;
            }
            break;
        case 'H':
            hash_mode = true;
            break;
        case 'q':
            quiet = true;
            break;
        case 'c':
            use_colors = false;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    /* Handle hash mode */
    if (hash_mode) {
        if (optind >= argc) {
            fprintf(stderr, "Error: --hash requires at least one file\n");
            return 1;
        }

        /* Default to fastest algorithm */
        if (!selected_impl) {
            selected_impl = crc_simd_available() ? &implementations[3]
                                                 : &implementations[2];
        }

        int errors = 0;
        for (int i = optind; i < argc; i++) {
            errors += hash_file(argv[i], selected_impl, quiet);
        }
        return errors > 0 ? 1 : 0;
    }

    /* Handle file benchmark mode (compare all implementations on real content)
     */
    if (optind < argc) {
        int errors = 0;
        for (int i = optind; i < argc; i++) {
            errors += benchmark_file(argv[i], iterations);
        }
        return errors > 0 ? 1 : 0;
    }

    /* Default mode: full benchmark suite */
    printf("%s", use_colors ? COLOR_BOLD : "");
    printf("╔═══════════════════════════════════════════════════════════╗\n");
    printf("║         crcspeed v%s - CRC Performance Suite          ║\n",
           CRCSPEED_VERSION);
    printf("╚═══════════════════════════════════════════════════════════╝\n");
    printf("%s", use_colors ? COLOR_RESET : "");

    print_system_info();

    int result = run_verification();
    if (result != 0) {
        printf("\n%sVerification failed! Skipping benchmarks.%s\n",
               use_colors ? COLOR_RED : "", use_colors ? COLOR_RESET : "");
        return result;
    }

    result = run_benchmarks(buffer_size, iterations);

    printf("\n");
    return result;
}
