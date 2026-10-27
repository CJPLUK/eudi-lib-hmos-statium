/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * status_list_token_fetcher.cj
 *
 * Ported from iOS Sources/Status/StatusListTokenFetcher.swift (actor StatusListTokenFetcher).
 *
 * Fetches a status list token from a URL, verifies its signature, and decodes
 * it into StatusListTokenClaims.
 *
 * iOS actor StatusListTokenFetcher -> Cangjie class.
 *
 * Call flow:
 *   getStatusClaims(url, format, nowSecs, clockSkew)
 *     -> fetch raw bytes from URL (via NetworkingServiceType)
 *     -> verify signature (via VerifyStatusListTokenSignature)
 *     -> decode JWT (parseJwtStatusListClaims) or CWT (decodeCwtStatusListToken)
 *     -> return StatusListTokenClaims
 */
package ohos_app_cangjie_eudi_cjstatium.statium.status

import ohos_app_cangjie_eudi_cjstatium.statium.model.*
import ohos_app_cangjie_eudi_cjstatium.statium.crypto.VerifyStatusListTokenSignature
import ohos_app_cangjie_eudi_cjstatium.statium.network.NetworkingServiceType
import ohos_app_cangjie_eudi_cjstatium.statium.network.NetworkingService
import ohos_app_cangjie_eudi_cjstatium.statium.util.*

/**
 * Interface for fetching status list token claims.
 * Mirrors iOS protocol StatusListTokenFetcherType.
 */
public interface StatusListTokenFetcherType {
    /**
     * Fetch and decode the status list token from the given URL.
     *
     * - url:       absolute URL string of the status list token endpoint
     * - format:    Jwt or Cwt
     * - nowSecs:   current time as seconds since epoch (for iat/exp validation)
     * - clockSkew: tolerance in seconds
     *
     * Returns StatusListTokenClaims on success.
     * Throws StatusError on any failure.
     */
    func getStatusClaims(
        url: String,
        format: StatusListTokenFormat,
        nowSecs: Float64,
        clockSkew: Float64
    ): StatusListTokenClaims
}

/**
 * Concrete fetcher backed by a NetworkingService and a verifier.
 * Mirrors iOS actor StatusListTokenFetcher.
 */
public class StatusListTokenFetcher <: StatusListTokenFetcherType {

    private let _networkingService: NetworkingServiceType
    private let _verifier: VerifyStatusListTokenSignature
    private let _nowSecs: Float64   // injection point for testing (mirrors iOS Date())

    /**
     * Primary constructor.
     *
     * - networkingService: HTTP client; defaults to NetworkingService()
     * - verifier:          signature verifier supplied by the caller
     * - nowSecs:           current time; pass -1.0 to use system clock
     */
    public init(
        networkingService!: NetworkingServiceType,
        verifier!: VerifyStatusListTokenSignature,
        nowSecs!: Float64
    ) {
        _networkingService = networkingService
        _verifier = verifier
        _nowSecs = nowSecs
    }

    /** Convenience: uses default NetworkingService and system clock. */
    public static func create(verifier: VerifyStatusListTokenSignature): StatusListTokenFetcher {
        return StatusListTokenFetcher(
            networkingService: NetworkingService(),
            verifier: verifier,
            nowSecs: -1.0
        )
    }

    public func getStatusClaims(
        url: String,
        format: StatusListTokenFormat,
        nowSecs: Float64,
        clockSkew: Float64
    ): StatusListTokenClaims {
        let effectiveNow: Float64 = if (_nowSecs >= 0.0) { _nowSecs } else { nowSecs }
        return getClaims(url, format, effectiveNow, clockSkew)
    }

    private func getClaims(
        url: String,
        format: StatusListTokenFormat,
        nowSecs: Float64,
        clockSkew: Float64
    ): StatusListTokenClaims {
        // Fetch raw bytes
        let headers: Array<(String, String)> = [("Accept", format.fieldHeaderValue())]
        let rawBytes = _networkingService.get(url, headers)

        // Verify signature (throws StatusError on failure)
        _verifier.verify(rawBytes, format, nowSecs)

        // Decode claims
        match (format) {
            case StatusListTokenFormat.Jwt =>
                let compact = String.fromUtf8(rawBytes)
                return parseJwtStatusListClaims(compact, url, nowSecs, clockSkew)
            case StatusListTokenFormat.Cwt =>
                return decodeCwtStatusListToken(rawBytes, Some(url), nowSecs, clockSkew)
        }
    }
}
