// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Profile for V8's PKEY-based sandbox trap fuzzer (--sandbox-trap-fuzzing).
//
// The trap fuzzer uses Intel Memory Protection Keys to intercept in-sandbox
// memory reads at random intervals via SIGVTALRM + SIGSEGV. When a read is
// intercepted, the value is mutated (bitflip, increment, random replace, or
// negation) before execution continues. This finds bugs where corrupted
// in-sandbox data leads to out-of-sandbox memory corruption.
//
// Unlike the regular sandbox fuzzer which uses JS-level memory corruption,
// this fuzzer operates at the hardware level and doesn't need a post-processor.
// Instead, we want to generate maximally diverse programs that exercise many
// different in-sandbox memory read paths through V8's internals.

let v8TrapFuzzingProfile = Profile(
    processArgs: { randomize in
        var args = v8ProcessArgs(randomize: randomize, forSandbox: true)

        // Enable the PKEY-based trap fuzzing mode.
        // This implies --sandbox-fuzzing already.
        args.append("--sandbox-trap-fuzzing")

        return args
    },

    processArgsReference: nil,

    processEnv: [
        "ASAN_OPTIONS": "abort_on_error=1:handle_sigill=1:symbolize=false:redzone=128",
        "LD_BIND_NOW": "1",
        "GLIBC_TUNABLES": "glibc.pthread.rseq=0",
    ],

    maxExecsBeforeRespawn: 1000,

    // The trap fuzzer adds significant overhead from signal handling and
    // single-stepping (each deferred mutation steps through N instructions).
    timeout: Timeout.interval(1500, 2500),

    codePrefix: """
        """,

    codeSuffix: """
        """,

    ecmaVersion: ECMAScriptVersion.es6,

    startupTests: [
        // Check that the fuzzilli integration is available.
        // NOTE: Startup tests run before the trap fuzzer timer has a chance to
        // fire (very short execution), so these should be reliable.
        ("fuzzilli('FUZZILLI_PRINT', 'test')", .shouldSucceed),

        // Crashes that indicate a sandbox violation should be detected.
        // Wild write outside sandbox.
        ("fuzzilli('FUZZILLI_CRASH', 3)", .shouldCrash),
        // ASan-detectable use-after-free.
        ("fuzzilli('FUZZILLI_CRASH', 4)", .shouldCrash),
        // ASan-detectable out-of-bounds write.
        ("fuzzilli('FUZZILLI_CRASH', 6)", .shouldCrash),
        // abort_with_sandbox_violation().
        ("fuzzilli('FUZZILLI_CRASH', 9)", .shouldCrash),
        // Invalid machine code instruction.
        ("fuzzilli('FUZZILLI_CRASH', 11)", .shouldCrash),

        // Crashes that are NOT sandbox violations and should be filtered.
        // IMMEDIATE_CRASH.
        ("fuzzilli('FUZZILLI_CRASH', 0)", .shouldNotCrash),
        // CHECK failure.
        ("fuzzilli('FUZZILLI_CRASH', 1)", .shouldNotCrash),
        // DCHECK failure.
        ("fuzzilli('FUZZILLI_CRASH', 2)", .shouldNotCrash),
        // libc++ hardening.
        ("fuzzilli('FUZZILLI_CRASH', 5)", .shouldNotCrash),
        // ud2 (release assert).
        ("fuzzilli('FUZZILLI_CRASH', 10)", .shouldNotCrash),
        // DEBUG should not be defined.
        ("fuzzilli('FUZZILLI_CRASH', 8)", .shouldSucceed),
    ],

    additionalCodeGenerators: [
        (ForceJITCompilationThroughLoopGenerator, 10),
        (ForceTurboFanCompilationGenerator, 10),
        (ForceMaglevCompilationGenerator, 10),
        (ForceOsrGenerator, 5),
        (V8GcGenerator, 10),
        (WasmStructGenerator, 10),
        (WasmArrayGenerator, 10),
        (SharedObjectGenerator, 5),
        (PretenureAllocationSiteGenerator, 5),
        (HoleNanGenerator, 5),
        (UndefinedNanGenerator, 5),
        (StringShapeGenerator, 5),
        (HeapNumberGenerator, 5),
    ],

    additionalProgramTemplates: WeightedList<ProgramTemplate>([
        (MapTransitionFuzzer, 2),
        (ValueSerializerFuzzer, 1),
        (V8RegExpFuzzer, 1),
        (WasmFastCallFuzzer, 1),
        (FastApiCallFuzzer, 1),
        (LazyDeoptFuzzer, 2),
        (WasmDeoptFuzzer, 1),
        (WasmTurbofanFuzzer, 1),
        (ProtoAssignSeqOptFuzzer, 1),
        (TurbofanTierUpNonInlinedCallFuzzer, 1),
    ]),

    disabledCodeGenerators: [],

    disabledMutators: ["ExplorationMutator", "ProbingMutator"],

    additionalBuiltins: [
        "gc": .function([.opt(gcOptions.instanceType)] => (.undefined | .jsPromise)),
        "d8": .object(),
        "Worker": .constructor(
            [.jsAnything, .object()] => .object(withMethods: ["postMessage", "getMessage"])),
    ],

    additionalObjectGroups: [jsD8, jsD8Test, jsD8FastCAPI, gcOptions],

    additionalEnumerations: [.gcTypeEnum, .gcExecutionEnum],

    // No post-processor needed: the trap fuzzer mutates memory reads at the hardware level.
    optionalPostProcessor: nil
)
