/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * base64url_util.cj
 *
 * Ported from iOS Sources/Extensions/Data+Extenstions.swift (fromBase64URL,
 * base64URLEncodedString) and Sources/Utilities/JWT.swift (base64URLDecode).
 *
 * Delegates to eudi_lib_core_crypto Base64Url for actual codec work.
 */
package ohos_app_cangjie_eudi_cjstatium.statium.util

import eudi_lib_core_crypto.Base64Url
import ohos_app_cangjie_eudi_cjstatium.statium.model.StatusError

/**
 * Decode a base64url string (no padding required) to bytes.
 * Returns None if the input is not valid base64url.
 *
 * Mirrors iOS Data.fromBase64URL(_:) -> [UInt8]?
 */
public func fromBase64Url(text: String): ?Array<UInt8> {
    try {
        return Some(Base64Url.decode(text))
    } catch (_: Exception) {
        return None
    }
}

/**
 * Decode a base64url string to bytes, throwing StatusError on failure.
 * Mirrors iOS Data.base64URLDecode(_:) throws.
 */
public func decodeBase64Url(text: String): Array<UInt8> {
    match (fromBase64Url(text)) {
        case Some(bytes) => return bytes
        case None => throw StatusError("InvalidBase64Url")
    }
}

/**
 * Encode bytes as base64url without padding.
 * Mirrors iOS Data.base64URLEncodedString().
 */
public func encodeBase64Url(data: Array<UInt8>): String {
    return Base64Url.encode(data)
}
