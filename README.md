# crcspeed

CRC be slow.

This make CRC be fast.

No original ideas, but original adaptations. Lots of shoulder standing.

This started out as a modified version of comment at http://stackoverflow.com/questions/20562546
then was made more extensible.

**NOTE**: You should not be using any CRC variant for new code anywhere. All new fast hashing code
should use [well-designed multi-platform simd-aware libraries like `xxh3` and `xxh128`](https://github.com/Cyan4973/xxHash). Only use CRC in your code if you need to hack together adapters for existing poorly designed systems or if you find yourself time travelling back to the 1970s.

## Performance Update 2025

Finally added SIMD for CRC-64-Jones and CRC-16-CCITT.

The SIMD improvements speed up CRC64 processing from 1.5 GB/s to 40+ GB/s and CRC16 procesisng from 1.5 GB/s to 9+ GB/s.

```haskell
mkdir build
cd build
cmake ..

./crc_bench 33333333
===================
CRC Benchmark Suite
===================

SIMD support: YES
Buffer size:  33333333 bytes (31.79 MB)
Iterations:   100

CRC64 Benchmarks:
-----------------
  crc64 (bit-by-bit)      :    71.96 MB/s,  0.32 cycles/byte
  crc64_lookup (table)    :   378.39 MB/s,  0.06 cycles/byte
  crc64speed (slice-8)    :  1432.05 MB/s,  0.02 cycles/byte
  crc64_simd (PCLMUL)     : 41997.47 MB/s,  0.00 cycles/byte

CRC16 Benchmarks:
-----------------
  crc16 (bit-by-bit)      :   110.53 MB/s,  0.21 cycles/byte
  crc16_lookup (table)    :   335.39 MB/s,  0.07 cycles/byte
  crc16speed (slice-8)    :  1416.56 MB/s,  0.02 cycles/byte
  crc16_simd (PCLMUL)     :  9426.57 MB/s,  0.00 cycles/byte

Small Buffer Benchmarks (64 bytes):
-----------------------------------
  crc64speed (slice-8)    :  2277.01 MB/s,  0.01 cycles/byte
  crc64_simd (PCLMUL)     :  7174.70 MB/s,  0.00 cycles/byte
  crc16speed (slice-8)    :  2337.62 MB/s,  0.01 cycles/byte
  crc16_simd (PCLMUL)     :  7006.68 MB/s,  0.00 cycles/byte

Medium Buffer Benchmarks (4KB):
-------------------------------
  crc64speed (slice-8)    :  1468.52 MB/s,  0.02 cycles/byte
  crc64_simd (PCLMUL)     : 45002.88 MB/s,  0.00 cycles/byte
  crc16speed (slice-8)    :  1395.84 MB/s,  0.02 cycles/byte
  crc16_simd (PCLMUL)     : 11047.09 MB/s,  0.00 cycles/byte

Large Buffer Benchmarks (1MB):
------------------------------
  crc64speed (slice-8)    :  1457.24 MB/s,  0.02 cycles/byte
  crc64_simd (PCLMUL)     : 42405.88 MB/s,  0.00 cycles/byte
  crc16speed (slice-8)    :  1418.09 MB/s,  0.02 cycles/byte
  crc16_simd (PCLMUL)     :  9431.78 MB/s,  0.00 cycles/byte
===================
```

CRC-via-SIMD usage for modern x64 and ARM64/NEON platforms:

```
/* CRC64 SIMD functions - use Jones polynomial 0xad93d23594c935a9 */
void crc64_simd_init(void);
uint64_t crc64_simd(uint64_t crc, const void *data, uint64_t len);

/* CRC16 SIMD functions - use CRC-16-CCITT polynomial 0x1021 */
void crc16_simd_init(void);
uint16_t crc16_simd(uint16_t crc, const void *data, uint64_t len);
```

Also improved the `crcspeed` output with more utility and reporting options as well (run `crcspeed --help` for full options):

```haskell
./crcspeed -n 1 ~/Downloads/Blame\!\ by\ Tsutomu\ Nihei\ Collection.zip

═══════════════════════════════════════════════════════════════════════
Benchmark: /Users/matt/Downloads/Blame! by Tsutomu Nihei Collection.zip
═══════════════════════════════════════════════════════════════════════
  File Size:   11.02 GB (11831396389 bytes)
  Iterations:  1
  Total Data:  11.02 GB per algorithm

  CRC64 Results:
  Algorithm       CRC Value                   MB/s        GB/s    Cycles/B  Status
  ──────────────  ──────────────────  ────────────  ──────────  ──────────  ──────
  crc64           0xfadd0161b519b53e         71.93        0.07       0.318  [PASS]
  crc64_lookup    0xfadd0161b519b53e        375.62        0.37       0.061  [PASS]
  crc64speed      0xfadd0161b519b53e       1455.17        1.42       0.016  [PASS]
  crc64_simd      0xfadd0161b519b53e      41937.87       40.95       0.001  [PASS]

  CRC16 Results:
  Algorithm       CRC Value                   MB/s        GB/s    Cycles/B  Status
  ──────────────  ──────────────────  ────────────  ──────────  ──────────  ──────
  crc16           0x9770                    111.92        0.11       0.204  [PASS]
  crc16_lookup    0x9770                    334.97        0.33       0.068  [PASS]
  crc16speed      0x9770                   1397.31        1.36       0.016  [PASS]
  crc16_simd      0x9770                   9268.78        9.05       0.002  [PASS]

  Summary:
  CRC64: 0xfadd0161b519b53e PASS
  CRC16: 0x9770             PASS

  Speedup (SIMD vs Table):
  CRC64: 28.8x
  CRC16: 6.6x
═══════════════════════════════════════════════════════════════════════
```

## Features

- CRC processing in 8-byte steps for CRC-64 (Jones) and CRC-16 (CCITT).
- Generates CRCs with overhead of 1.5 CPU cycles per byte
- Little endian and big endian support
  - big endian support hasn't been tested yet (because `qemu-system-sparc` hates me).
- Test suite generates comparison for: bit-by-bit calculation, byte-by-byte calcuation
  (Sarwate / lookup table), and 8-bytes-at-once calculation. Results are reported
  with resulting CRCs, throughput, and CPU cycles per byte comparisons.
- newest, 2025: SIMD CRC support (though, requires custom implementation per CRC type so isn't a "generic CRC speedup framework" like `crcspeed` itself for slicing table generation)

## Usage

- Use little endian CRCs:
  - `crc64speed_init();`
  - `crc64speed(old_crc, new_data, new_data_length);`
  - `crc16speed_init();`
  - `crc16speed(old_crc, new_data, new_data_length);`
- Use native architecture CRCs:
  - `crc64speed_init_native();`
  - `crc64speed_native(old_crc, new_data, new_data_length);`
  - `crc16speed_init_native();`
  - `crc16speed_native(old_crc, new_data, new_data_length);`
- Use custom CRC64 variant:
  - `crcspeed64native_init(crc_calculation_function, uint64_t populate[8][256]);`
    - crc calculation function takes (0, data, data_len) and returns crc64 as `uint64_t`.
    - `populate` is a lookup table \_init populates for future lookups.
  - `crcspeed64native(populated_lookup_table, old_crc, new_data, new_data_length);`
- Use custom CRC16 parameters:
  - `crcspeed16native_init(crc_calculation_function, uint16_t populate[8][256]);`
    - crc calculation function takes (0, data, data_len) and returns crc16 as `uint16_t`.
  - `crcspeed16native(populated_lookup_table, old_crc, new_data, new_data_length);`

Additionally, there are specific functions for forcing little or big endian calculations:
`crcspeed64little_init()`, `crcspeed64little()`, `crc64big_init()`, `crcspeed64big()`,
`crcspeed16little_init()`, `crcspeed16little()`, `crc16big_init()`, `crcspeed16big()`.

## Architecture

- `crcspeed.c` is a _framework_ for bootstrapping a fast lookup table using an existing function
  used to return the CRC for byte values 0 to 255. Lookups then use fast lookup table to
  calculate CRCs 8 bytes per loop iteration.
- `crc64speed.c` is a ready-to-use fast, self-contained CRC-64-Jones implementation.
- `crc16speed.c` is a ready-to-use fast, self-contained CRC16-CCITT implementation.
- when in a multithreaded environment, do not run initialization function(s) in parallel.
- for fastest CRC calculations, you can force the entire CRC lookup table into
  CPU caches by running `crc64speed_cache_table()` or `crc16speed_cache_table()`.
  Those functions just iterate over the lookup table to bring everything into local
  caches out from main memory (or worse, paged out to disk).
- The CRC-16 lookup table is 4 KB (8x256 16 bit entries = 8 _ 256 _ 2 bytes = 4096 bytes).
- The CRC-64 lookup table is 16 KB (8x256 64 bit entires = 8 _ 256 _ 8 bytes = 16384 bytes).

## Benchmark

The Makefile builds three test excutables:

- `crc64speed` just returns check values for two input types across all
  three internal CRC process methods (bit-by-bit, byte-by-byte, 8-bytes-at-once).
- `crc16speed` returns check values for the same data, except limited to CRC16 results.
- `crcspeed` has two options:
  - no arguments: return check values for crc64 and crc16 at the same time.
  - one argument: filename of file to read into memory then run CRC tests against.
    - If CRC results do not match (for each CRC variant), the return value of
      `crcspeed` is 1, otherwise 0 on success.

```haskell
> mkdir build
> cd build
> cmake ..
> make -j
[ 18%] Building C object CMakeFiles/crcspeed.dir/crc16speed.c.o
[ 27%] Building C object CMakeFiles/crcspeed.dir/crcspeed.c.o
[ 36%] Building C object CMakeFiles/crcspeed.dir/crc64speed.c.o
[ 54%] Building C object CMakeFiles/crc64speed.dir/crc64speed.c.o
[ 54%] Building C object CMakeFiles/crc64speed.dir/crcspeed.c.o
[ 54%] Building C object CMakeFiles/crc16speed.dir/crcspeed.c.o
[ 63%] Building C object CMakeFiles/crc16speed.dir/crc16speed.c.o
[ 72%] Building C object CMakeFiles/crcspeed.dir/main.c.o
[ 81%] Linking C executable crc64speed
[ 90%] Linking C executable crc16speed
[100%] Linking C executable crcspeed
[100%] Built target crc16speed
[100%] Built target crc64speed
[100%] Built target crcspeed

> ./crcspeed ~/Downloads/John\ Mayer\ -\ Live\ At\ Austin\ City\ Limits\ PBS\ -\ Full\ Concert-gcdUz12FkdQ.mp4
Comparing CRCs against 730.72 MB file...

crc64 (no table)
CRC = ee43263b0a2b6c60
7.142642 seconds at 102.30 MB/s (24.18 CPU cycles per byte)

crc64 (lookup table)
CRC = ee43263b0a2b6c60
1.777920 seconds at 411.00 MB/s (6.02 CPU cycles per byte)

crc64speed
CRC = ee43263b0a2b6c60
0.448819 seconds at 1628.09 MB/s (1.52 CPU cycles per byte)

crc16 (no table)
CRC = 000000000000490f
7.413062 seconds at 98.57 MB/s (25.10 CPU cycles per byte)

crc16 (lookup table)
CRC = 000000000000490f
1.951917 seconds at 374.36 MB/s (6.61 CPU cycles per byte)

crc16speed
CRC = 000000000000490f
0.441418 seconds at 1655.38 MB/s (1.49 CPU cycles per byte)
```

## License

All work here is released under BSD or Apache 2.0 License or equivalent.

## Thanks

Thanks to Mark Adler for providing a readable implementation of slicing-by-8 in a [stackoverflow comment](http://stackoverflow.com/questions/20562546/how-to-get-crc64-distributed-calculation-use-its-linearity-property/20579405#20579405).

Thanks for [pycrc](https://github.com/tpircher/pycrc) for saving me another month figuring out how to write CRC-64-Jones by hand.

Thanks to [A PAINLESS GUIDE TO CRC ERROR DETECTION ALGORITHMS](http://www.zlib.net/crc_v3.txt) for providing so many details it was clear I should give up and not try to re-create everything myself.
