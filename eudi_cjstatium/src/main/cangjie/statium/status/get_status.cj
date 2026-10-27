/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * get_status.cj
 *
 * Ported from iOS Sources/Status/GetStatus.swift (actor GetStatus).
 *
 * Top-level API: given a status list URL and an index (or a StatusReference),
 * returns the CredentialStatus at that index.
 *
 * iOS actor GetStatus -> Cangjie class.
 *
 * Flow (mirrors iOS GetStatus.processStatusClaims):
 *   1. fetchClaims → StatusListTokenClaims
 *   2. Base64Url-decode claims.statusList.compressedList → raw DEFLATE bytes
 *   3. Decompress DEFLATE → byte array
 *   4. ReadStatus.readStatus(at: index) → raw byte
 *   5. CredentialStatus.fromByte(raw) → CredentialStatus
 */
package ohos_app_cangjie_eudi_cjstatium.statium.status

import ohos_app_cangjie_eudi_cjstatium.statium.model.*
import ohos_app_cangjie_eudi_cjstatium.statium.util.*

/**
 * A closure type for fetching status list token claims from a URL.
 * Mirrors iOS typealias FetchClaimsHandler.
 *
 * Parameters:
 *   format    - Jwt or Cwt
 *   url       - absolute URL string
 *   nowSecs   - current time (seconds since epoch) for validation
 *   clockSkew - tolerance in seconds
 * Returns: StatusListTokenClaims (throws StatusError on failure)
 */
public type FetchClaimsHandler = (StatusListTokenFormat, String, Float64, Float64) -> StatusListTokenClaims

/**
 * Interface for retrieving a CredentialStatus.
 * Mirrors iOS protocol GetStatusType.
 */
public interface GetStatusType {
    /**
     * Get the status at `index` from the status list at `url`.
     * Throws StatusError on any failure.
     */
    func getStatus(
        index: Int64,
        url: String,
        format: StatusListTokenFormat,
        fetchClaims: FetchClaimsHandler,
        nowSecs: Float64,
        clockSkew: Float64
    ): CredentialStatus

    /**
     * Convenience overload using a StatusReference.
     * Mirrors iOS GetStatus.getStatus(session:reference:format:fetchClaims:clockSkew:).
     */
    func getStatus(
        reference: StatusReference,
        format: StatusListTokenFormat,
        fetchClaims: FetchClaimsHandler,
        nowSecs: Float64,
        clockSkew: Float64
    ): CredentialStatus
}

/**
 * Concrete implementation.
 * Mirrors iOS actor GetStatus.
 */
public class GetStatus <: GetStatusType {

    public init() {}

    public func getStatus(
        index: Int64,
        url: String,
        format: StatusListTokenFormat,
        fetchClaims: FetchClaimsHandler,
        nowSecs: Float64,
        clockSkew: Float64
    ): CredentialStatus {
        let claims = fetchClaims(format, url, nowSecs, clockSkew)
        return processStatusClaims(claims, index)
    }

    public func getStatus(
        reference: StatusReference,
        format: StatusListTokenFormat,
        fetchClaims: FetchClaimsHandler,
        nowSecs: Float64,
        clockSkew: Float64
    ): CredentialStatus {
        let claims = fetchClaims(format, reference.uri, nowSecs, clockSkew)
        return processStatusClaims(claims, reference.idx)
    }

    /**
     * Decode the status byte from the claims.
     * Mirrors iOS GetStatus.processStatusClaims.
     *
     * Steps:
     *   1. Base64Url-decode the compressedList field -> raw DEFLATE bytes
     *   2. Decompress DEFLATE -> uncompressed byte array
     *   3. ReadStatus.readStatus(at: index) -> raw UInt8
     *   4. CredentialStatus.fromByte -> CredentialStatus
     */
    private func processStatusClaims(claims: StatusListTokenClaims, index: Int64): CredentialStatus {
        // Step 1: Decode base64url -> compressed bytes
        let compressedBytes: Array<UInt8>
        match (fromBase64Url(claims.statusList.compressedList)) {
            case Some(b) => compressedBytes = b
            case None => throw StatusError("BadBytes:base64url decode failed")
        }

        // Step 2: Decompress DEFLATE
        let decompressed = decompressDeflate(compressedBytes)
        if (decompressed.size == 0) {
            throw StatusError("BadBytes:decompression produced empty output")
        }

        // Step 3: Read status bit at index
        let rs = ReadStatus(bitsPerStatus: claims.statusList.bitsPerStatus, byteArray: decompressed)
        match (rs.readStatus(index)) {
            case Some(rawByte) => return CredentialStatus.fromByte(rawByte)
            case None => throw StatusError("OutOfRange:index=" + index.toString())
        }
    }
}
