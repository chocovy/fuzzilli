#!/bin/bash
#
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Build script for V8 PKEY-based sandbox trap fuzzer.
# Requirements:
#   - Linux x64 only (uses Intel Memory Protection Keys)
#   - CPU must support PKEY (check: grep pku /proc/cpuinfo)

if [ "$(uname)" != "Linux" ]; then
    echo "Error: The trap fuzzer is only supported on Linux x64 (requires Intel PKEY)"
    exit 1
fi

if ! grep -q "pku" /proc/cpuinfo 2>/dev/null; then
    echo "Warning: CPU does not appear to support PKU. The trap fuzzer may not work."
fi

PATCH_DIR="$(dirname "$0")/Patches"
for patch in "$PATCH_DIR"/*.patch; do
    [ -f "$patch" ] || continue
    echo "Applying patch: $(basename "$patch")"
    git apply "$patch" || { echo "Failed to apply $(basename "$patch")"; exit 1; }
done

gn gen out/fuzzbuild-trap --args='is_debug=false dcheck_always_on=false v8_static_library=true v8_enable_verify_heap=true v8_enable_partition_alloc=false v8_fuzzilli=true v8_enable_sandbox_hardware_support=true v8_enable_memory_corruption_api=true sanitizer_coverage_flags="trace-pc-guard" target_cpu="x64" is_asan=true'

ninja -C ./out/fuzzbuild-trap d8
