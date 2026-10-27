/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * statium_types.cj
 *
 * Ported from iOS:
 *   Types/BitsPerStatus.swift
 *   Types/StatusList.swift
 *   Types/StatusListTokenClaims.swift
 *   Types/StatusReference.swift
 *   Types/StatusListTokenFormat.swift
 *   Types/CredentialStatus.swift
 *   Types/Errors.swift
 *   Types/Byte.swift
 *
 * iOS actor -> Cangjie class (no actor keyword in Cangjie; thread-safety via caller).
 */
package ohos_app_cangjie_eudi_cjstatium.statium.model

import ohos_app_cangjie_eudi_cjstatium.statium.spec.TokenStatusListSpec

// ---------------------------------------------------------------------------
// Byte alias
// ---------------------------------------------------------------------------
public type Byte = UInt8

// ---------------------------------------------------------------------------
// BitsPerStatus
// Ported from iOS enum BitsPerStatus: Int { case one=1, two=2, four=4, eight=8 }
// ---------------------------------------------------------------------------

/**
 * Number of bits used per status entry in the status list byte array.
 * Allowed values: 1, 2, 4, 8.
 */
public enum BitsPerStatus {
    | One    // 1 bit per status  (rawValue = 1)
    | Two    // 2 bits per status (rawValue = 2)
    | Four   // 4 bits per status (rawValue = 4)
    | Eight  // 8 bits per status (rawValue = 8)

    /** Integer raw value matching the iOS enum rawValue. */
    public func rawValue(): Int64 {
        match (this) {
            case One   => 1
            case Two   => 2
            case Four  => 4
            case Eight => 8
        }
    }

    /** Create from raw integer (1/2/4/8).  Returns None for invalid values. */
    public static func fromRawValue(v: Int64): ?BitsPerStatus {
        if (v == 1) { return Some(One) }
        if (v == 2) { return Some(Two) }
        if (v == 4) { return Some(Four) }
        if (v == 8) { return Some(Eight) }
        return None
    }
}

// ---------------------------------------------------------------------------
// BitsPerStatus bit-position helpers
// Ported from iOS ReadStatus.swift extension BitsPerStatus
// ---------------------------------------------------------------------------

/**
 * Calculate the byte position and bit position within that byte for the
 * status at `index`.
 *
 * Returns (bytePosition, bitPosition).
 */
public func byteAndBitPosition(bps: BitsPerStatus, index: Int64): (Int64, Int64) {
    let bitsPerEntry = bps.rawValue()
    let statusesPerByte: Int64 = 8 / bitsPerEntry
    let bytePosition: Int64 = index / statusesPerByte
    let positionInByte: Int64 = index % statusesPerByte
    let bitPosition: Int64 = positionInByte * bitsPerEntry
    return (bytePosition, bitPosition)
}

/**
 * Extract the status value from `statusByte` at the given `bitPosition`.
 *
 * Applies a mask of width bitsPerEntry, shifted left by bitPosition, then
 * shifts the result right to normalise.
 */
public func readStatusByte(bps: BitsPerStatus, statusByte: UInt8, bitPosition: Int64): UInt8 {
    let baseMask: Int64 = match (bps) {
        case One   => 0b00000001
        case Two   => 0b00000011
        case Four  => 0b00001111
        case Eight => 0b11111111
    }
    let shifted = (Int64(statusByte) & (baseMask << bitPosition)) >> bitPosition
    return UInt8(shifted)
}

// ---------------------------------------------------------------------------
// StatusList
// Ported from iOS struct StatusList: Codable
// ---------------------------------------------------------------------------

/**
 * A compressed status list entry.
 *
 * - bitsPerStatus: bits used per entry (1/2/4/8)
 * - compressedList: base64url-encoded DEFLATE-compressed byte array
 * - aggregationUri: optional aggregation URI
 *
 * JSON keys: { "bits": N, "lst": "<b64url>", "aggregation_uri": "..." }
 * CWT keys : { "bits": N, "lst": <bstr>, "aggregation_uri": "..." }
 */
public class StatusList {
    public let bitsPerStatus: BitsPerStatus
    public let compressedList: String   // base64url-encoded (JWT) or raw (CWT — normalised to b64url)
    public let aggregationUri: ?String

    public init(
        bitsPerStatus!: BitsPerStatus,
        compressedList!: String,
        aggregationUri!: ?String
    ) {
        this.bitsPerStatus = bitsPerStatus
        this.compressedList = compressedList
        this.aggregationUri = aggregationUri
    }
}

// ---------------------------------------------------------------------------
// StatusListTokenClaims
// Ported from iOS struct StatusListTokenClaims: Codable
// ---------------------------------------------------------------------------

/**
 * Claims extracted from a status list token (JWT or CWT).
 *
 * Claim name mapping (JSON / CWT):
 *   sub  / 2    = subject
 *   iat  / 6    = issuedAt   (seconds since epoch)
 *   exp  / 4    = expirationTime (optional)
 *   ttl  / 65534 = timeToLive (optional, seconds)
 *   status_list / 65533 = statusList
 */
public class StatusListTokenClaims {
    public let subject: String
    public let issuedAt: Float64          // seconds since epoch (iOS TimeInterval)
    public let expirationTime: ?Float64
    public let timeToLive: ?Float64
    public let statusList: StatusList

    public init(
        subject!: String,
        issuedAt!: Float64,
        expirationTime!: ?Float64,
        timeToLive!: ?Float64,
        statusList!: StatusList
    ) {
        this.subject = subject
        this.issuedAt = issuedAt
        this.expirationTime = expirationTime
        this.timeToLive = timeToLive
        this.statusList = statusList
    }

    /**
     * Validate claims:
     *   1. subject must match the fetch URI
     *   2. issuedAt must not be in the future (± clockSkew)
     *   3. if exp present, must not be expired (± clockSkew)
     *
     * Returns self on success; throws StatusError on failure.
     * (Mirrors iOS extension StatusListTokenClaims.ensureValid)
     */
    public func ensureValid(uri: String, nowSecs: Float64, clockSkew: Float64): StatusListTokenClaims {
        if (uri != this.subject) {
            throw StatusError("BadSubject:" + this.subject)
        }
        match (this.expirationTime) {
            case Some(exp) =>
                if (nowSecs > exp + clockSkew) {
                    throw StatusError("ExpiredToken")
                }
            case None => ()
        }
        let iatDate = this.issuedAt
        if (iatDate - clockSkew > nowSecs) {
            throw StatusError("InvalidIssueDate")
        }
        return this
    }
}

// ---------------------------------------------------------------------------
// StatusReference
// Ported from iOS struct StatusReference: Codable
// ---------------------------------------------------------------------------

/**
 * A reference to a specific status entry in a status list token.
 *
 * JSON: { "idx": <int>, "uri": "<url>" }
 */
public class StatusReference {
    public let idx: Int64
    public let uri: String   // absolute URI string (iOS URL.absoluteString)

    public init(idx!: Int64, uri!: String) {
        this.idx = idx
        this.uri = uri
    }
}

// ---------------------------------------------------------------------------
// StatusListTokenFormat
// Ported from iOS enum StatusListTokenFormat
// ---------------------------------------------------------------------------

/**
 * Token format: JWT or CWT.
 */
public enum StatusListTokenFormat {
    | Jwt
    | Cwt

    /** The Accept header value for this format. */
    public func fieldHeaderValue(): String {
        match (this) {
            case Jwt => TokenStatusListSpec.mediaTypeApplicationStatusListJWT
            case Cwt => TokenStatusListSpec.mediaTypeApplicationStatusListCWT
        }
    }
}

// ---------------------------------------------------------------------------
// CredentialStatus
// Ported from iOS enum CredentialStatus
// ---------------------------------------------------------------------------

/**
 * The decoded status of a credential at a specific index in the status list.
 *
 * Mirrors iOS CredentialStatus with identical case semantics.
 */
public enum CredentialStatus {
    | Valid
    | Invalid
    | Suspended
    | ApplicationSpecific(UInt8)
    | Reserved(UInt8)

    /** Byte value of this status. */
    public func toByte(): UInt8 {
        match (this) {
            case Valid                    => TokenStatusListSpec.statusValid
            case Invalid                  => TokenStatusListSpec.statusInvalid
            case Suspended                => TokenStatusListSpec.statusSuspended
            case ApplicationSpecific(v)   => v
            case Reserved(v)              => v
        }
    }

    /** Create CredentialStatus from a raw byte value. */
    public static func fromByte(value: UInt8): CredentialStatus {
        if (value == TokenStatusListSpec.statusValid)     { return Valid }
        if (value == TokenStatusListSpec.statusInvalid)   { return Invalid }
        if (value == TokenStatusListSpec.statusSuspended) { return Suspended }
        if (isApplicationSpecific(value))                 { return ApplicationSpecific(value) }
        return Reserved(value)
    }

    private static func isApplicationSpecific(value: UInt8): Bool {
        return value == TokenStatusListSpec.statusApplicationSpecific
            || (value >= TokenStatusListSpec.statusApplicationSpecificRangeStart
                && value <= TokenStatusListSpec.statusApplicationSpecificRangeEnd)
    }
}

// ---------------------------------------------------------------------------
// StatusError
// Ported from iOS enum StatusError: LocalizedError
// ---------------------------------------------------------------------------

/**
 * Error type for the statium library.
 *
 * Collapses iOS enum cases into a single Exception with a descriptive message,
 * because Cangjie does not have associated-value enum exceptions.
 */
public class StatusError <: Exception {
    public init(message: String) {
        super(message)
    }
}
