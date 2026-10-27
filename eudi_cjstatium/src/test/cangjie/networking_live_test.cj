/*
 * networking_live_test.cj
 *
 * REAL network integration tests for NetworkingService.
 *
 * Unlike the mock-backed coverage tests, these exercise the actual HTTP+TLS
 * path of NetworkingService.get on-device against a known-reachable HTTPS
 * endpoint (issuer.eudiw.dev). They verify the TLS-configured Client built in
 * NetworkingService.init() can complete a real request end-to-end.
 *
 * Each case retries up to 3 times to absorb transient DNS/network jitter.
 */
package ohos_app_cangjie_eudi_cjstatium.statium.test

import std.unittest.*
import std.unittest.testmacro.*

import ohos_app_cangjie_eudi_cjstatium.statium.model.*
import ohos_app_cangjie_eudi_cjstatium.statium.network.*

// A reachable, stable HTTPS endpoint returning a large JSON body that
// always contains the "credential_issuer" key.
let LIVE_OK_URL = "https://issuer.eudiw.dev/.well-known/openid-credential-issuer"
// A path on the same host that returns a non-200 (404).
let LIVE_404_URL = "https://issuer.eudiw.dev/.well-known/does-not-exist"

let NO_HEADERS: Array<(String, String)> = []

// ---------------------------------------------------------------------------
// Retry helper: run a body up to `attempts` times, returning the last success.
// Re-throws the final exception if every attempt fails.
// ---------------------------------------------------------------------------
func withRetry<T>(attempts: Int64, body: () -> T): T {
    var lastErr: ?Exception = None
    var i = 0
    while (i < attempts) {
        try {
            return body()
        } catch (e: Exception) {
            lastErr = Some(e)
        }
        i = i + 1
    }
    match (lastErr) {
        case Some(e) => throw e
        case None => throw Exception("withRetry: no attempts ran")
    }
}

// ---------------------------------------------------------------------------
// Test 1: real GET via concrete NetworkingService — non-empty body containing
// the "credential_issuer" key. Validates the full HTTP + TLS path.
// ---------------------------------------------------------------------------
@Test
class NetworkingServiceLiveGetUT {

    @TestCase
    func testLiveGet_ok(): Unit {
        let svc = NetworkingService()
        let bytes = withRetry<Array<UInt8>>(3, { => svc.get(LIVE_OK_URL, NO_HEADERS) })

        @Expect(bytes.size > 0, true)

        let body = String.fromUtf8(bytes)
        @Expect(body.contains("credential_issuer"), true)
    }
}

// ---------------------------------------------------------------------------
// Test 2: same call but through the interface type NetworkingServiceType,
// covering the interface-binding dispatch path on a real request.
// ---------------------------------------------------------------------------
@Test
class NetworkingServiceTypeLiveGetUT {

    @TestCase
    func testLiveGet_viaInterface(): Unit {
        let svc: NetworkingServiceType = NetworkingService()
        let bytes = withRetry<Array<UInt8>>(3, { => svc.get(LIVE_OK_URL, NO_HEADERS) })

        @Expect(bytes.size > 0, true)

        let body = String.fromUtf8(bytes)
        @Expect(body.contains("credential_issuer"), true)
    }
}

// ---------------------------------------------------------------------------
// Test 3: error path — a 404 URL must throw StatusError (non-200 response).
// Retries cover transport jitter; a 404 status itself is deterministic so the
// catch is reached on the first reachable attempt.
// ---------------------------------------------------------------------------
@Test
class NetworkingServiceLive404UT {

    @TestCase
    func testLiveGet_404Throws(): Unit {
        let svc = NetworkingService()
        var caught = false
        try {
            withRetry<Array<UInt8>>(3, { => svc.get(LIVE_404_URL, NO_HEADERS) })
        } catch (e: StatusError) {
            caught = true
        }
        @Expect(caught, true)
    }
}
