/* CRC Benchmark Suite
 *
 * Benchmarks all CRC implementations and compares throughput.
 */

#include "crc16speed.h"
#include "crc64speed.h"
#include "crc_simd.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

/* Get current time in microseconds */
static long long ustime(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((long long)tv.tv_sec) * 1000000 + tv.tv_usec;
}

/* Cycle counter for more precise measurements */
#if __aarch64__
static inline uint64_t rdtsc(void) {
    uint64_t val;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(val));
    return val;
}
__attribute__((unused)) static inline uint64_t get_freq(void) {
    uint64_t freq;
    __asm__ volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    return freq;
}
#elif defined(__x86_64__) || defined(_M_X64)
static inline uint64_t rdtsc(void) {
    unsigned int lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
__attribute__((unused)) static inline uint64_t get_freq(void) {
    return 0; /* Frequency detection is complex on x86 */
}
#else
static inline uint64_t rdtsc(void) {
    return 0;
}
__attribute__((unused)) static inline uint64_t get_freq(void) {
    return 0;
}
#endif

typedef uint64_t (*crc64_fn)(uint64_t, const void *, uint64_t);
typedef uint16_t (*crc16_fn)(uint16_t, const void *, uint64_t);

typedef struct {
    const char *name;
    crc64_fn fn64;
    crc16_fn fn16;
} benchmark_entry_t;

static void run_benchmark_64(const char *name, crc64_fn fn, const void *data,
                             size_t len, int iterations) {
    /* Warm up */
    volatile uint64_t result = 0;
    for (int i = 0; i < 10; i++) {
        result ^= fn(0, data, len);
    }

    /* Actual benchmark */
    long long start = ustime();
    uint64_t start_cycles = rdtsc();

    for (int i = 0; i < iterations; i++) {
        result ^= fn(0, data, len);
    }

    uint64_t end_cycles = rdtsc();
    long long end = ustime();

    double total_bytes = (double)len * iterations;
    double total_mb = total_bytes / (1024.0 * 1024.0);
    double total_seconds = (end - start) / 1e6;
    double throughput = total_mb / total_seconds;
    double cycles_per_byte = (double)(end_cycles - start_cycles) / total_bytes;

    printf("  %-24s: %8.2f MB/s, %5.2f cycles/byte\n", name, throughput,
           cycles_per_byte);
    (void)result;
}

static void run_benchmark_16(const char *name, crc16_fn fn, const void *data,
                             size_t len, int iterations) {
    /* Warm up */
    volatile uint16_t result = 0;
    for (int i = 0; i < 10; i++) {
        result ^= fn(0, data, len);
    }

    /* Actual benchmark */
    long long start = ustime();
    uint64_t start_cycles = rdtsc();

    for (int i = 0; i < iterations; i++) {
        result ^= fn(0, data, len);
    }

    uint64_t end_cycles = rdtsc();
    long long end = ustime();

    double total_bytes = (double)len * iterations;
    double total_mb = total_bytes / (1024.0 * 1024.0);
    double total_seconds = (end - start) / 1e6;
    double throughput = total_mb / total_seconds;
    double cycles_per_byte = (double)(end_cycles - start_cycles) / total_bytes;

    printf("  %-24s: %8.2f MB/s, %5.2f cycles/byte\n", name, throughput,
           cycles_per_byte);
    (void)result;
}

int main(int argc, char *argv[]) {
    size_t buffer_size = 1024 * 1024; /* 1 MB default */
    int iterations = 100;

    if (argc > 1) {
        buffer_size = strtoull(argv[1], NULL, 0);
    }
    if (argc > 2) {
        iterations = atoi(argv[2]);
    }

    printf("CRC Benchmark Suite\n");
    printf("===================\n\n");
    printf("SIMD support: %s\n", crc_simd_available() ? "YES" : "NO");
    printf("Buffer size:  %zu bytes (%.2f MB)\n", buffer_size,
           buffer_size / (1024.0 * 1024.0));
    printf("Iterations:   %d\n\n", iterations);

    /* Initialize tables */
    crc64speed_init();
    crc16speed_init();
    crc64_simd_init();
    crc16_simd_init();

    /* Allocate and fill buffer */
    uint8_t *buffer = malloc(buffer_size);
    if (!buffer) {
        fprintf(stderr, "Failed to allocate %zu bytes\n", buffer_size);
        return 1;
    }

    srand(12345);
    for (size_t i = 0; i < buffer_size; i++) {
        buffer[i] = rand() & 0xff;
    }

    /* CRC64 benchmarks */
    printf("CRC64 Benchmarks:\n");
    printf("-----------------\n");
    run_benchmark_64("crc64 (bit-by-bit)", crc64, buffer, buffer_size,
                     iterations / 100 + 1);
    run_benchmark_64("crc64_lookup (table)", crc64_lookup, buffer, buffer_size,
                     iterations);
    run_benchmark_64("crc64speed (slice-8)", crc64speed, buffer, buffer_size,
                     iterations);
    run_benchmark_64("crc64_simd (PCLMUL)", crc64_simd, buffer, buffer_size,
                     iterations);

    /* CRC16 benchmarks */
    printf("\nCRC16 Benchmarks:\n");
    printf("-----------------\n");
    run_benchmark_16("crc16 (bit-by-bit)", crc16, buffer, buffer_size,
                     iterations / 100 + 1);
    run_benchmark_16("crc16_lookup (table)", crc16_lookup, buffer, buffer_size,
                     iterations);
    run_benchmark_16("crc16speed (slice-8)", crc16speed, buffer, buffer_size,
                     iterations);
    run_benchmark_16("crc16_simd (PCLMUL)", crc16_simd, buffer, buffer_size,
                     iterations);

    /* Small buffer benchmarks (to show SIMD startup cost) */
    printf("\nSmall Buffer Benchmarks (64 bytes):\n");
    printf("-----------------------------------\n");
    run_benchmark_64("crc64speed (slice-8)", crc64speed, buffer, 64,
                     iterations * 10000);
    run_benchmark_64("crc64_simd (PCLMUL)", crc64_simd, buffer, 64,
                     iterations * 10000);
    run_benchmark_16("crc16speed (slice-8)", crc16speed, buffer, 64,
                     iterations * 10000);
    run_benchmark_16("crc16_simd (PCLMUL)", crc16_simd, buffer, 64,
                     iterations * 10000);

    printf("\nMedium Buffer Benchmarks (4KB):\n");
    printf("-------------------------------\n");
    run_benchmark_64("crc64speed (slice-8)", crc64speed, buffer, 4096,
                     iterations * 100);
    run_benchmark_64("crc64_simd (PCLMUL)", crc64_simd, buffer, 4096,
                     iterations * 100);
    run_benchmark_16("crc16speed (slice-8)", crc16speed, buffer, 4096,
                     iterations * 100);
    run_benchmark_16("crc16_simd (PCLMUL)", crc16_simd, buffer, 4096,
                     iterations * 100);

    /* Large buffer benchmarks (1MB - main test) */
    printf("\nLarge Buffer Benchmarks (1MB):\n");
    printf("------------------------------\n");
    run_benchmark_64("crc64speed (slice-8)", crc64speed, buffer, buffer_size,
                     iterations);
    run_benchmark_64("crc64_simd (PCLMUL)", crc64_simd, buffer, buffer_size,
                     iterations);
    run_benchmark_16("crc16speed (slice-8)", crc16speed, buffer, buffer_size,
                     iterations);
    run_benchmark_16("crc16_simd (PCLMUL)", crc16_simd, buffer, buffer_size,
                     iterations);

    free(buffer);
    return 0;
}
