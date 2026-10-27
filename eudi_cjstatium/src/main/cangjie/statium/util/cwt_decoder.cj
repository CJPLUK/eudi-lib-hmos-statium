/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * cwt_decoder.cj
 *
 * Ported from iOS Sources/Utilities/CWT.swift (struct CWTDecoder).
 *
 * Decodes a COSE_Sign1-wrapped CWT (CBOR Web Token) carrying Token Status
 * List claims.
 *
 * Structure: COSE_Sign1 = tag(18, array[4]):
 *   [0] protected header (bstr containing CBOR map)
 *   [1] unprotected header (CBOR map)
 *   [2] payload (bstr containing CWT claims map)
 *   [3] signature (bstr)
 *
 * CWT claim numbers:
 *   2     = sub  (utf8String)
 *   4     = exp  (unsignedInt, seconds since epoch)
 *   6     = iat  (unsignedInt, seconds since epoch)
 *   65533 = status_list (map: { bits, lst, aggregation_uri })
 *   65534 = ttl  (unsignedInt, seconds)
 *
 * COSE header 16 = typ
 *
 * Delegates CBOR decoding to ohos_app_cangjie_eudi_cjcbor (CborValue / decodeCbor).
 */
package ohos_app_cangjie_eudi_cjstatium.statium.util

import ohos_app_cangjie_eudi_cjcbor.cbor.*
import ohos_app_cangjie_eudi_cjstatium.statium.model.*

/**
 * Decode a COSE_Sign1-wrapped CWT status list token.
 *
 * Mirrors iOS CWTDecoder.decodeStatusListToken(from: Data, fetchedFrom: URL?, clockSkew: TimeInterval).
 *
 * Parameters:
 *   data      - raw CWT bytes
 *   fetchedFrom - optional URI string used to validate the sub claim
 *   nowSecs   - current time (seconds since epoch) for iat/exp validation
 *   clockSkew - tolerance in seconds
 *
 * Throws StatusError on any structural or validation failure.
 */
public func decodeCwtStatusListToken(
    data: Array<UInt8>,
    fetchedFrom: ?String,
    nowSecs: Float64,
    clockSkew: Float64
): StatusListTokenClaims {
    let root = decodeCbor(data)

    // Unwrap COSE_Sign1: tag(18, ...) or bare array of 4
    let coseArray: CborValue
    match (root) {
        case TaggedVal(tag, inner) =>
            if (tag != 18u64) {
                throw StatusError("CwtNotCoseSign1:tag=" + tag.toString())
            }
            coseArray = inner
        case ArrayVal(_) =>
            coseArray = root
        case _ =>
            throw StatusError("CwtNotCoseSign1")
    }

    // coseArray must be an array of exactly 4 elements
    match (coseArray) {
        case ArrayVal(arr) =>
            if (arr.size != 4) {
                throw StatusError("CwtInvalidCoseStructure:len=" + arr.size.toString())
            }
        case _ =>
            throw StatusError("CwtInvalidCoseStructure")
    }

    // Element 0: protected header (bstr -> CBOR map)
    let protectedBstr = requireCoseElement(coseArray, 0, "protected")
    let protectedHeaderBytes: Array<UInt8>
    match (protectedBstr) {
        case ByteStringVal(b) => protectedHeaderBytes = b
        case _ => throw StatusError("CwtProtectedHeaderNotBstr")
    }

    // Element 1: unprotected header (CBOR map)
    let unprotectedCbor = requireCoseElement(coseArray, 1, "unprotected")

    // Validate typ == "application/statuslist+cwt" (preferred in protected header)
    validateCoseType(protectedHeaderBytes, unprotectedCbor)

    // Element 2: payload (bstr containing CWT claims CBOR map)
    let payloadBstr = requireCoseElement(coseArray, 2, "payload")
    let payloadBytes: Array<UInt8>
    match (payloadBstr) {
        case ByteStringVal(b) => payloadBytes = b
        case _ => throw StatusError("CwtPayloadNotBstr")
    }

    // Decode payload as CBOR map
    let payloadCbor = decodeCbor(payloadBytes)
    let claimsMap: CborValue
    match (payloadCbor) {
        case MapVal(_) => claimsMap = payloadCbor
        case _ => throw StatusError("CwtPayloadNotMap")
    }

    // Extract claims
    let sub = extractCwtUtf8Claim(claimsMap, 2u64, "sub")
    let iatRaw = extractCwtUIntClaim(claimsMap, 6u64, "iat")
    let iat = Float64(iatRaw)
    let expOpt = extractCwtOptionalUIntClaim(claimsMap, 4u64)
    let exp: ?Float64 = match (expOpt) {
        case Some(v) => Some(Float64(v))
        case None => None
    }
    let ttlOpt = extractCwtOptionalUIntClaim(claimsMap, 65534u64)
    let ttl: ?Float64 = match (ttlOpt) {
        case Some(v) => Some(Float64(v))
        case None => None
    }

    // Validate iat / exp / sub
    validateCwtClaims(sub, iat, exp, fetchedFrom, nowSecs, clockSkew)

    // Extract status_list claim (CWT label 65533)
    let statusListOpt = cborMapGet(claimsMap, UInt64Val(65533u64))
    let statusListCbor: CborValue = match (statusListOpt) {
        case Some(v) => v
        case None => throw StatusError("CwtMissingStatusList")
    }

    let statusList = decodeCwtStatusList(statusListCbor)

    return StatusListTokenClaims(
        subject: sub,
        issuedAt: iat,
        expirationTime: exp,
        timeToLive: ttl,
        statusList: statusList
    )
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

func requireCoseElement(coseArray: CborValue, index: Int64, name: String): CborValue {
    match (coseArray.at(index)) {
        case Some(v) => return v
        case None => throw StatusError("CwtMissingElement:" + name)
    }
}

/**
 * Validate that the COSE_Sign1 protected or unprotected header contains
 *   typ == "application/statuslist+cwt"
 * (COSE header label 16).
 */
func validateCoseType(protectedBytes: Array<UInt8>, unprotected: CborValue): Unit {
    let expected = "application/statuslist+cwt"

    // Try protected header
    if (protectedBytes.size > 0) {
        try {
            let protectedMap = decodeCbor(protectedBytes)
            match (extractCoseTyp(protectedMap)) {
                case Some(typ) =>
                    if (typ == expected) { return }
                case None => ()
            }
        } catch (_: Exception) { () }
    }

    // Try unprotected header
    match (extractCoseTyp(unprotected)) {
        case Some(typ) =>
            if (typ == expected) { return }
        case None => ()
    }

    throw StatusError("CwtInvalidType")
}

/**
 * Extract the "typ" string from a COSE header map.
 * COSE label 16 (unsigned int) maps to the "typ" parameter.
 */
func extractCoseTyp(headerCbor: CborValue): ?String {
    match (headerCbor) {
        case MapVal(pairs) =>
            var i: Int64 = 0
            while (i < pairs.size) {
                let pair = pairs[i]
                let k = pair[0]
                let v = pair[1]
                match (k) {
                    case UInt64Val(label) =>
                        if (label == 16u64) {
                            match (v) {
                                case TextStringVal(s) => return Some(s)
                                case ByteStringVal(b) => return Some(String.fromUtf8(b))
                                case _ => return None
                            }
                        }
                    case _ => ()
                }
                i = i + 1
            }
            return None
        case _ => return None
    }
}

/**
 * Decode the status_list CWT map value into a StatusList.
 *
 * Keys: "bits" (string), "lst" (bstr), "aggregation_uri" (string, optional).
 * Mirrors iOS CWTDecoder.decodeStatusList(from: [CBOR: CBOR]).
 */
func decodeCwtStatusList(statusListCbor: CborValue): StatusList {
    match (statusListCbor) {
        case MapVal(pairs) =>
            var bits: ?BitsPerStatus = None
            var lstBytes: ?Array<UInt8> = None
            var aggUri: ?String = None

            var i: Int64 = 0
            while (i < pairs.size) {
                let pair = pairs[i]
                let k = pair[0]
                let v = pair[1]
                match (k) {
                    case TextStringVal(ks) =>
                        if (ks == "bits") {
                            match (v) {
                                case UInt64Val(b) =>
                                    bits = BitsPerStatus.fromRawValue(Int64(b))
                                case _ => ()
                            }
                        } else if (ks == "lst") {
                            match (v) {
                                case ByteStringVal(b) => lstBytes = Some(b)
                                case _ => ()
                            }
                        } else if (ks == "aggregation_uri") {
                            match (v) {
                                case TextStringVal(u) => aggUri = Some(u)
                                case _ => ()
                            }
                        }
                    case _ => ()
                }
                i = i + 1
            }

            let bps: BitsPerStatus = match (bits) {
                case Some(b) => b
                case None => throw StatusError("CwtInvalidBitsValue")
            }
            let rawLst: Array<UInt8> = match (lstBytes) {
                case Some(b) => b
                case None => throw StatusError("CwtInvalidListBytes")
            }

            // Normalise to base64url string to match JWT representation
            let lstB64 = encodeBase64Url(rawLst)
            return StatusList(
                bitsPerStatus: bps,
                compressedList: lstB64,
                aggregationUri: aggUri
            )
        case _ => throw StatusError("CwtStatusListNotMap")
    }
}

// ---------------------------------------------------------------------------
// CBOR map field helpers
// ---------------------------------------------------------------------------

/** Look up a value in a CborValue MapVal by key. Returns None if not a map or key absent. */
func cborMapGet(mapVal: CborValue, key: CborValue): ?CborValue {
    return mapVal.field(key)
}

/** Extract a mandatory utf8String claim by its unsigned-int label. */
func extractCwtUtf8Claim(mapVal: CborValue, label: UInt64, name: String): String {
    let keyVal = UInt64Val(label)
    match (cborMapGet(mapVal, keyVal)) {
        case Some(TextStringVal(s)) => return s
        case _ => throw StatusError("CwtMissingClaim:" + name)
    }
}

/** Extract a mandatory unsignedInt claim by its unsigned-int label. */
func extractCwtUIntClaim(mapVal: CborValue, label: UInt64, name: String): UInt64 {
    let keyVal = UInt64Val(label)
    match (cborMapGet(mapVal, keyVal)) {
        case Some(UInt64Val(v)) => return v
        case _ => throw StatusError("CwtMissingClaim:" + name)
    }
}

/** Extract an optional unsignedInt claim by its unsigned-int label. */
func extractCwtOptionalUIntClaim(mapVal: CborValue, label: UInt64): ?UInt64 {
    let keyVal = UInt64Val(label)
    match (cborMapGet(mapVal, keyVal)) {
        case Some(UInt64Val(v)) => return Some(v)
        case _ => return None
    }
}

// ---------------------------------------------------------------------------
// Claim validation (mirrors iOS CWTDecoder.validateClaims)
// ---------------------------------------------------------------------------

/**
 * ASCII-lowercase a string. URL scheme and host are case-insensitive
 * (RFC 3986 §3.1, §3.2.2), so iOS's URLComponents normalises them. We only
 * touch A-Z (URLs use ASCII hosts; IDN/punycode is already ASCII).
 */
func asciiLower(s: String): String {
    let chars = s.toRuneArray()
    var out = Array<Rune>(chars.size, repeat: r' ')
    var i: Int64 = 0
    while (i < chars.size) {
        let cp = UInt32(chars[i])
        if (cp >= 0x41u32 && cp <= 0x5Au32) {
            out[i] = Rune(cp + 0x20u32)
        } else {
            out[i] = chars[i]
        }
        i = i + 1
    }
    return String(out)
}

/**
 * Extract the canonical origin (scheme://host[:port]) from a URL string.
 *
 * Mirrors iOS CWTDecoder.originString(_ url: URL), which builds the string from
 * URLComponents with path/query/fragment cleared. URLComponents normalises:
 *   - scheme lower-cased
 *   - host lower-cased
 *   - userinfo (`user:pass@`) is NOT part of the origin string produced here
 *     (originString clears path/query/fragment; user/password are dropped when
 *     comparing against `sub`, which is a bare origin)
 *   - default ports are NOT serialised by URLComponents (443 for https, 80 for
 *     http) — they are absent from `.string`
 *
 * Strategy (no stdx.encoding.url dependency):
 *   1. Split scheme on "://".
 *   2. Authority = everything up to first '/', '?' or '#'.
 *   3. Drop any "userinfo@" prefix from the authority.
 *   4. Split host/port on the last ':' (only when the remainder is all digits,
 *      so IPv6-less hosts are safe; ports here are numeric).
 *   5. Lower-case scheme and host; strip the default port for the scheme.
 *   6. Re-assemble scheme://host[:port].
 */
public func extractUrlOrigin(url: String): String {
    let schemeMarker = "://"
    let urlChars = url.toRuneArray()
    let markerChars = schemeMarker.toRuneArray()
    let urlLen = urlChars.size
    let markerLen = markerChars.size

    var markerPos: Int64 = -1
    var i: Int64 = 0
    while (i <= urlLen - markerLen) {
        var matched = true
        var k: Int64 = 0
        while (k < markerLen) {
            if (UInt32(urlChars[i + k]) != UInt32(markerChars[k])) {
                matched = false
                break
            }
            k = k + 1
        }
        if (matched) {
            markerPos = i
            break
        }
        i = i + 1
    }

    if (markerPos < 0) {
        // No "://" found: return the whole string as-is (best-effort).
        return url
    }

    // scheme = chars[0..markerPos)
    var scheme = ""
    if (markerPos > 0) {
        var schemeChars = Array<Rune>(markerPos, repeat: r' ')
        var s: Int64 = 0
        while (s < markerPos) {
            schemeChars[s] = urlChars[s]
            s = s + 1
        }
        scheme = String(schemeChars)
    }

    // authority starts right after "://", ends at first '/', '?' or '#'.
    let authStart: Int64 = markerPos + markerLen
    var authEnd: Int64 = authStart
    while (authEnd < urlLen) {
        let cp = UInt32(urlChars[authEnd])
        if (cp == 0x2Fu32 || cp == 0x3Fu32 || cp == 0x23u32) { // '/' '?' '#'
            break
        }
        authEnd = authEnd + 1
    }

    var authChars = Array<Rune>(authEnd - authStart, repeat: r' ')
    var a: Int64 = 0
    while (authStart + a < authEnd) {
        authChars[a] = urlChars[authStart + a]
        a = a + 1
    }
    var authority = String(authChars)

    // Drop "userinfo@" prefix (last '@' wins, matching URI authority grammar).
    let atIdx = lastIndexOfRune(authority, r'@')
    if (atIdx >= 0) {
        authority = substringFrom(authority, atIdx + 1)
    }

    // Split host[:port] on the last ':' iff the suffix is all-digits (a port).
    var host = authority
    var port = ""
    let colonIdx = lastIndexOfRune(authority, r':')
    if (colonIdx >= 0) {
        let portCand = substringFrom(authority, colonIdx + 1)
        if (isAllDigits(portCand)) {
            host = substringTo(authority, colonIdx)
            port = portCand
        }
    }

    scheme = asciiLower(scheme)
    host = asciiLower(host)

    // Strip default ports (URLComponents omits them).
    if ((scheme == "https" && port == "443") || (scheme == "http" && port == "80")) {
        port = ""
    }

    if (port == "") {
        return scheme + "://" + host
    }
    return scheme + "://" + host + ":" + port
}

/** Index of the last occurrence of `target` in `s`, or -1. */
func lastIndexOfRune(s: String, target: Rune): Int64 {
    let chars = s.toRuneArray()
    var i: Int64 = chars.size - 1
    while (i >= 0) {
        if (chars[i] == target) {
            return i
        }
        i = i - 1
    }
    return -1
}

/** Substring from index `start` (inclusive) to end. */
func substringFrom(s: String, start: Int64): String {
    let chars = s.toRuneArray()
    if (start >= chars.size) {
        return ""
    }
    var out = Array<Rune>(chars.size - start, repeat: r' ')
    var i: Int64 = start
    while (i < chars.size) {
        out[i - start] = chars[i]
        i = i + 1
    }
    return String(out)
}

/** Substring from 0 to index `end` (exclusive). */
func substringTo(s: String, end: Int64): String {
    let chars = s.toRuneArray()
    var out = Array<Rune>(end, repeat: r' ')
    var i: Int64 = 0
    while (i < end) {
        out[i] = chars[i]
        i = i + 1
    }
    return String(out)
}

/** True iff `s` is non-empty and every char is an ASCII digit. */
func isAllDigits(s: String): Bool {
    let chars = s.toRuneArray()
    if (chars.size == 0) {
        return false
    }
    var i: Int64 = 0
    while (i < chars.size) {
        let cp = UInt32(chars[i])
        if (cp < 0x30u32 || cp > 0x39u32) {
            return false
        }
        i = i + 1
    }
    return true
}

public func validateCwtClaims(
    subject: String,
    issuedAt: Float64,
    expiration: ?Float64,
    fetchedFrom: ?String,
    nowSecs: Float64,
    clockSkew: Float64
): Unit {
    // The token's `sub` and the URL it was fetched from must share the same
    // ORIGIN (scheme+host+port). Both legitimately carry a status-list path, so
    // compare normalized origins on BOTH sides — this is the cross-origin
    // forgery check. extractUrlOrigin now lowercases scheme/host and strips
    // default ports (443/80), so HTTPS://Host:443 and https://host match.
    match (fetchedFrom) {
        case Some(uri) =>
            let fetchedOrigin = extractUrlOrigin(uri)
            let subjectOrigin = extractUrlOrigin(subject)
            if (fetchedOrigin != subjectOrigin) {
                throw StatusError("CwtSubjectMismatch:expected=" + fetchedOrigin + ",got=" + subjectOrigin)
            }
        case None => ()
    }

    // iat must not be in the future (allow skew)
    if (issuedAt > nowSecs + clockSkew) {
        throw StatusError("CwtIssuedAtInFuture")
    }

    // exp (if present) must not be expired (allow skew)
    match (expiration) {
        case Some(exp) =>
            if (exp < nowSecs - clockSkew) {
                throw StatusError("CwtExpired")
            }
        case None => ()
    }
}
