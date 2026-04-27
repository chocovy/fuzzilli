# V8 Trap Fuzzing Target

This target builds V8 for the PKEY-based sandbox trap fuzzer (`--sandbox-trap-fuzzing`).

## Overview

The trap fuzzer uses Intel Memory Protection Keys (PKEY) to intercept random
in-sandbox memory reads at the hardware level. When a read is intercepted, the
value is mutated before execution continues. This can find bugs where corrupted
in-sandbox data causes out-of-sandbox memory corruption (sandbox violations).

### How it works

1. A virtual timer (ITIMER_VIRTUAL) fires at random intervals (~50ms CPU time)
2. The SIGVTALRM handler removes read access to the sandbox's PKEY
3. The next in-sandbox memory read triggers SIGSEGV (SEGV_PKUERR)
4. The SIGSEGV handler mutates the value being read, restores PKEY access, and continues

### Mutation strategies
- Fully random 32-bit value
- Single bit flip
- Increment/decrement with magnitude matching
- Value negation

## Requirements

- **Linux x64 only** (uses Intel Memory Protection Keys)
- CPU must support PKU (`grep pku /proc/cpuinfo`)
- ASan/UBSan enabled for detecting out-of-sandbox corruption

## Building

```bash
cd aspect/v8
source aspect/aspect/aspect aspect
aspect aspect aspect aspect-trap
```

Or manually from the V8 source directory:

```bash
gn gen out/fuzzbuild-trap --args='is_debug=false dcheck_always_on=false v8_static_library=true v8_enable_verify_heap=true v8_enable_partition_alloc=false v8_fuzzilli=true v8_enable_sandbox_hardware_support=true v8_enable_memory_corruption_api=true sanitizer_coverage_flags="trace-pc-guard" target_cpu="x64" is_asan=true is_ubsan=true'
ninja -C ./out/fuzzbuild-trap d8
```

## Running

```bash
swift run FuzzilliCli --profile=v8TrapFuzzing --storagePath=/path/to/output /path/to/v8/out/fuzzbuild-trap/d8
```

## Notes

- Crashes are **not reproducible** from the trap fuzzer alone — the output is a
  log of mutations that must be manually reconstructed
- The trap fuzzer's signal handling may conflict with CPU profiler — profiling
  is automatically disabled when trap fuzzing is active
- `dcheck_always_on=false` is used because the trap fuzzer intentionally corrupts
  memory reads, which would trigger DCHECKs unrelated to real bugs
