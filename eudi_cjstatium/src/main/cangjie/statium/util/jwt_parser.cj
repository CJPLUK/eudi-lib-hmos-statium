/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * jwt_parser.cj
 *
 * Ported from iOS Sources/Utilities/JWT.swift.
 *
 * Parses a compact JWT (header.payload.signature) and decodes the JSON
 * claims into a StatusListTokenClaims.
 *
 * JSON parsing is done with stdx.encoding.json via JsonValue.fromStr.
 * JsonValue is a sealed abstract class; concrete subtypes are JsonNull,
 * JsonBool, JsonInt, JsonFloat, JsonString, JsonArray, JsonObject.
 * Pattern matching uses Cangjie type-pattern syntax:
 *   case jsonObj: JsonObject => ...
 */
package ohos_app_cangjie_eudi_cjstatium.statium.util

import stdx.encoding.json.*
import ohos_app_cangjie_eudi_cjstatium.statium.model.*
import ohos_app_cangjie_eudi_cjstatium.statium.spec.TokenStatusListSpec

/**
 * Internal structure holding the decoded parts of a compact JWT.
 * Mirrors iOS internal struct JWT.
 */
class JwtParts {
    let headerJson: String
    let payload: Array<UInt8>
    let signature: Array<UInt8>

    init(headerJson!: String, payload!: Array<UInt8>, signature!: Array<UInt8>) {
        this.headerJson = headerJson
        this.payload = payload
        this.signature = signature
    }
}

/**
 * Parse a compact JWT string "hdr.payload.sig" into its three decoded parts.
 * Throws StatusError("InvalidJWT") if the format is wrong.
 */
func parseCompactJwt(compact: String): JwtParts {
    let parts = compact.split(".")
    if (parts.size != 3) {
        throw StatusError("InvalidJWT")
    }
    let headerBytes = decodeBase64Url(parts[0])
    let payloadBytes = decodeBase64Url(parts[1])
    let sigBytes = decodeBase64Url(parts[2])

    let headerJson = String.fromUtf8(headerBytes)
    return JwtParts(headerJson: headerJson, payload: payloadBytes, signature: sigBytes)
}

/**
 * Parse the "typ" field from a JWT header JSON string.
 * Returns None if not present.
 */
func extractJwtHeaderTyp(headerJson: String): ?String {
    return extractJsonStringField(headerJson, "typ")
}

/**
 * Decode a JWT payload (base64url part 1) and extract StatusListTokenClaims.
 *
 * Mirrors iOS StatusListTokenFetcher.getAndEnsureClaims.
 *
 * Validates:
 *   - typ header == "statuslist+jwt"
 *   - sub matches uri
 *   - iat / exp with clockSkew
 *
 * Throws StatusError on any validation failure.
 */
public func parseJwtStatusListClaims(
    compact: String,
    uri: String,
    nowSecs: Float64,
    clockSkew: Float64
): StatusListTokenClaims {
    let jwt = parseCompactJwt(compact)

    // Validate typ header
    match (extractJwtHeaderTyp(jwt.headerJson)) {
        case Some(typ) =>
            if (typ != TokenStatusListSpec.mediaSubtypeStatusListJWT) {
                throw StatusError("BadJwtHeader:typ=" + typ)
            }
        case None =>
            throw StatusError("BadJwtHeader:missing typ")
    }

    let payloadJson = String.fromUtf8(jwt.payload)
    let claims = decodeStatusListTokenClaimsFromJson(payloadJson)
    return claims.ensureValid(uri, nowSecs, clockSkew)
}

/**
 * Decode StatusListTokenClaims from a JSON string.
 * JSON claim names: sub, iat, exp, ttl, status_list.{ bits, lst, aggregation_uri }
 */
func decodeStatusListTokenClaimsFromJson(json: String): StatusListTokenClaims {
    let root: JsonValue
    try {
        root = JsonValue.fromStr(json)
    } catch (e: Exception) {
        throw StatusError("JsonParseError:" + e.message)
    }

    let obj = requireJsonObject(root, "JWT payload")

    let sub = requireStringField(obj, "sub")
    let iat = requireNumberField(obj, "iat")
    let exp = optionalNumberField(obj, "exp")
    let ttl = optionalNumberField(obj, "ttl")

    let slField = requireField(obj, "status_list")
    let slObj = requireJsonObject(slField, "status_list")

    let bits = requireNumberField(slObj, "bits")
    let bitsInt = Int64(bits)
    let bpsOpt = BitsPerStatus.fromRawValue(bitsInt)
    let bps: BitsPerStatus = match (bpsOpt) {
        case Some(b) => b
        case None => throw StatusError("InvalidBitsValue:" + bitsInt.toString())
    }

    let lst = requireStringField(slObj, "lst")
    let aggUri = optionalStringField(slObj, "aggregation_uri")

    let statusList = StatusList(
        bitsPerStatus: bps,
        compressedList: lst,
        aggregationUri: aggUri
    )
    return StatusListTokenClaims(
        subject: sub,
        issuedAt: iat,
        expirationTime: exp,
        timeToLive: ttl,
        statusList: statusList
    )
}

// ---------------------------------------------------------------------------
// Minimal JSON helpers using stdx.encoding.json
// JsonValue is a sealed abstract class; subtypes: JsonNull, JsonBool,
// JsonInt, JsonFloat, JsonString, JsonArray, JsonObject.
// Type-pattern matching: `case jsonObj: JsonObject => jsonObj`
// ---------------------------------------------------------------------------

func requireJsonObject(v: JsonValue, ctx: String): JsonObject {
    match (v) {
        case jsonObj: JsonObject => return jsonObj
        case _ => throw StatusError("ExpectedJsonObject:" + ctx)
    }
}

func requireField(obj: JsonObject, name: String): JsonValue {
    match (obj.get(name)) {
        case Some(v) => return v
        case None => throw StatusError("MissingField:" + name)
    }
}

func requireStringField(obj: JsonObject, name: String): String {
    let v = requireField(obj, name)
    match (v) {
        case jsonStr: JsonString => return jsonStr.getValue()
        case _ => throw StatusError("ExpectedString:" + name)
    }
}

func requireNumberField(obj: JsonObject, name: String): Float64 {
    let v = requireField(obj, name)
    match (v) {
        case jsonF: JsonFloat => return jsonF.getValue()
        case jsonI: JsonInt => return Float64(jsonI.getValue())
        case _ => throw StatusError("ExpectedNumber:" + name)
    }
}

func optionalStringField(obj: JsonObject, name: String): ?String {
    match (obj.get(name)) {
        case Some(jsonStr: JsonString) => return Some(jsonStr.getValue())
        case _ => return None
    }
}

func optionalNumberField(obj: JsonObject, name: String): ?Float64 {
    match (obj.get(name)) {
        case Some(jsonF: JsonFloat) => return Some(jsonF.getValue())
        case Some(jsonI: JsonInt) => return Some(Float64(jsonI.getValue()))
        case _ => return None
    }
}

// ---------------------------------------------------------------------------
// Simple string field extraction without full JSON parse
// Used for header typ field
// ---------------------------------------------------------------------------

/**
 * Extract a top-level JSON string field value by key.
 *
 * Previously a hand-written character scanner; replaced with the stdx JSON
 * parser so escape handling, nesting and quoting match a real JSON decoder
 * (the scanner mishandled escapes inside other string values and only knew a
 * few escape sequences). Returns None if the JSON does not parse, is not an
 * object, the key is absent, or the value is not a string.
 */
func extractJsonStringField(json: String, key: String): ?String {
    let root: JsonValue
    try {
        root = JsonValue.fromStr(json)
    } catch (_: Exception) {
        return None
    }
    match (root) {
        case obj: JsonObject =>
            match (obj.get(key)) {
                case Some(jsonStr: JsonString) => return Some(jsonStr.getValue())
                case _ => return None
            }
        case _ => return None
    }
}
