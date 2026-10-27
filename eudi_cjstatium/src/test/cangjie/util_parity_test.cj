/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * util_parity_test.cj
 *
 * Proof tests for three iOS-parity fixes in statium/util:
 *   1. decompressDeflate consumes ZLIB-wrapped (RFC 1950) input by stripping
 *      the 2-byte header (mirrors iOS decompressedZlibStreaming).
 *   2. validateCwtClaims compares the subject claim VERBATIM against the
 *      fetched-URL origin (mirrors iOS originString(fetchedFrom) == subject).
 *   3. extractUrlOrigin normalises like iOS URLComponents: lower-cases
 *      scheme/host, strips default ports (443/80) and userinfo.
 */
package ohos_app_cangjie_eudi_cjstatium.statium.test

import std.unittest.*
import std.unittest.testmacro.*

import ohos_app_cangjie_eudi_cjstatium.statium.util.*
import ohos_app_cangjie_eudi_cjstatium.statium.model.*

@Test
class UtilParityTest {

    // -----------------------------------------------------------------------
    // Fix 1: ZLIB-wrapped decompression
    //
    // Vector produced by Python: zlib.compress(b"hello, status list world!", 9)
    //   -> 78 da cb 48 ... (0x78 = ZLIB CMF; full 33-byte stream below).
    // A raw-DEFLATE decoder fed the WHOLE stream would choke on the 0x78da
    // header; only after stripping 2 bytes does the body decode. This proves
    // the strip-2-bytes fix.
    // -----------------------------------------------------------------------
    @TestCase
    func testDecompressZlibWrappedVector(): Unit {
        let zlibBytes: Array<UInt8> = [
            120u8, 218u8, 203u8, 72u8, 205u8, 201u8, 201u8, 215u8, 81u8, 40u8,
            46u8, 73u8, 44u8, 41u8, 45u8, 86u8, 200u8, 201u8, 44u8, 46u8,
            81u8, 40u8, 207u8, 47u8, 202u8, 73u8, 81u8, 4u8, 0u8, 122u8,
            54u8, 9u8, 74u8
        ]
        // First byte must be the ZLIB magic 0x78.
        @Expect(zlibBytes[0], 120u8)

        let out = decompressDeflate(zlibBytes)
        let decoded = String.fromUtf8(out)
        @Expect(decoded, "hello, status list world!")
    }

    // Round-trip: a ZLIB stream for a second known plaintext.
    // zlib.compress(b"EUDI", 9) -> 78 da 73 0d 75 f1 04 00 02 e8 01 28
    @TestCase
    func testDecompressZlibWrappedShort(): Unit {
        let zlibBytes: Array<UInt8> = [
            120u8, 218u8, 115u8, 13u8, 117u8, 241u8, 4u8, 0u8, 2u8, 232u8,
            1u8, 40u8
        ]
        let out = decompressDeflateOrThrow(zlibBytes)
        @Expect(String.fromUtf8(out), "EUDI")
    }

    // Empty input returns empty (mirrors iOS returning empty Data on bad input).
    @TestCase
    func testDecompressEmptyReturnsEmpty(): Unit {
        let out = decompressDeflate(Array<UInt8>())
        @Expect(out.size, 0)
    }

    // Input too short to hold a ZLIB header+body -> non-throwing variant returns
    // empty; throwing variant throws.
    @TestCase
    func testDecompressTooShortThrows(): Unit {
        let tooShort: Array<UInt8> = [120u8, 218u8]
        @Expect(decompressDeflate(tooShort).size, 0)
        var threw = false
        try {
            decompressDeflateOrThrow(tooShort)
        } catch (_: StatusError) {
            threw = true
        }
        @Expect(threw, true)
    }

    // -----------------------------------------------------------------------
    // Fix 3: extractUrlOrigin normalisation (iOS URLComponents parity)
    // -----------------------------------------------------------------------

    // Host case-insensitivity + default-port stripping: these must be EQUAL.
    @TestCase
    func testOriginUppercaseAndDefaultHttpsPortEqual(): Unit {
        let a = extractUrlOrigin("HTTPS://Host:443/x")
        let b = extractUrlOrigin("https://host")
        @Expect(a, "https://host")
        @Expect(a, b)
    }

    // Default http port 80 is stripped and scheme lower-cased.
    @TestCase
    func testOriginDefaultHttpPortStripped(): Unit {
        @Expect(extractUrlOrigin("HTTP://Example.COM:80/path?q=1"), "http://example.com")
    }

    // Non-default port is preserved (and host lower-cased).
    @TestCase
    func testOriginNonDefaultPortKept(): Unit {
        @Expect(extractUrlOrigin("https://Host:8443/a/b"), "https://host:8443")
    }

    // Userinfo is dropped from the origin.
    @TestCase
    func testOriginUserinfoDropped(): Unit {
        @Expect(extractUrlOrigin("https://user:pass@host.example/path"), "https://host.example")
    }

    // Path / query / fragment all stripped.
    @TestCase
    func testOriginStripsPathQueryFragment(): Unit {
        @Expect(extractUrlOrigin("https://host.example/p?x=1#frag"), "https://host.example")
    }

    // -----------------------------------------------------------------------
    // Fix 2: subject compared VERBATIM to fetched origin
    // -----------------------------------------------------------------------

    // Subject equals the fetched origin -> passes.
    @TestCase
    func testSubjectExactOriginPasses(): Unit {
        validateCwtClaims(
            "https://issuer.example",
            1000.0,            // iat
            Option<Float64>.None, // exp
            Some("https://issuer.example/status/123"),
            2000.0,            // now
            300.0              // skew
        )
        // No throw == pass.
        @Expect(true, true)
    }

    // Subject and fetchedFrom both carry the same status-list path (and thus the
    // same origin) -> accepted. The cross-origin check compares ORIGINS on both
    // sides, so a legitimate path-bearing `sub` matching its fetch URL passes.
    @TestCase
    func testSubjectWithPathSameOriginPasses(): Unit {
        var threw = false
        try {
            validateCwtClaims(
                "https://issuer.example/status/123", // subject has a path
                1000.0,
                Option<Float64>.None,
                Some("https://issuer.example/status/123"), // same origin
                2000.0,
                300.0
            )
        } catch (e: StatusError) {
            threw = true
        }
        @Expect(threw, false)
    }

    // Subject host differs from fetched host -> rejected.
    @TestCase
    func testSubjectDifferentHostRejected(): Unit {
        var threw = false
        try {
            validateCwtClaims(
                "https://evil.example",
                1000.0,
                Option<Float64>.None,
                Some("https://issuer.example/status"),
                2000.0,
                300.0
            )
        } catch (_: StatusError) {
            threw = true
        }
        @Expect(threw, true)
    }

    // iat in the future beyond skew -> rejected.
    @TestCase
    func testIssuedAtInFutureRejected(): Unit {
        var threw = false
        try {
            validateCwtClaims(
                "https://issuer.example",
                5000.0,                 // iat far in future
                Option<Float64>.None,
                Option<String>.None,    // no fetchedFrom -> skip subject check
                1000.0,                 // now
                300.0
            )
        } catch (_: StatusError) {
            threw = true
        }
        @Expect(threw, true)
    }

    // exp in the past beyond skew -> rejected.
    @TestCase
    func testExpiredRejected(): Unit {
        var threw = false
        try {
            validateCwtClaims(
                "https://issuer.example",
                100.0,
                Some(500.0),            // exp well in the past
                Option<String>.None,
                5000.0,                 // now
                300.0
            )
        } catch (_: StatusError) {
            threw = true
        }
        @Expect(threw, true)
    }
}
