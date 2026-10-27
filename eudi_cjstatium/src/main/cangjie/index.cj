/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * index.cj — public surface of ohos_app_cangjie_eudi_cjstatium
 *
 * This file is the top-level entry for the cjpm package.  It imports the
 * sub-packages so their symbols are accessible to external consumers that
 * import ohos_app_cangjie_eudi_cjstatium.*, and provides a smoke-test
 * function used by the entry module.
 */
package ohos_app_cangjie_eudi_cjstatium

import ohos_app_cangjie_eudi_cjstatium.statium.model.*
import ohos_app_cangjie_eudi_cjstatium.statium.spec.*
import ohos_app_cangjie_eudi_cjstatium.statium.time.*
import ohos_app_cangjie_eudi_cjstatium.statium.crypto.*
import ohos_app_cangjie_eudi_cjstatium.statium.util.*
import ohos_app_cangjie_eudi_cjstatium.statium.network.*
import ohos_app_cangjie_eudi_cjstatium.statium.status.*

/**
 * Smoke-test function consumed by EntryView.
 * Exercises ReadStatus bit-accessor without network I/O.
 * Mirrors the iOS unit-test pattern: one 0xFF byte, bitsPerStatus=four,
 * indexes 0 and 1 should both return 0x0F.
 */
public func runStatiumDemo(): String {
    // Build a 1-byte status list: [0xFF] with 4-bit entries
    let byteArray: Array<UInt8> = [0xFFu8]
    let rs = ReadStatus(bitsPerStatus: BitsPerStatus.Four, byteArray: byteArray)

    let r0 = rs.readStatus(0)
    let r1 = rs.readStatus(1)
    let r2 = rs.readStatus(2)  // out of range for 1-byte / 4-bit

    var result = "Statium demo:\n"
    match (r0) {
        case Some(v) =>
            result = result + "index 0 = 0x" + hexByte(v) + "\n"
        case None =>
            result = result + "index 0 = nil\n"
    }
    match (r1) {
        case Some(v) =>
            result = result + "index 1 = 0x" + hexByte(v) + "\n"
        case None =>
            result = result + "index 1 = nil\n"
    }
    match (r2) {
        case Some(v) =>
            result = result + "index 2 = 0x" + hexByte(v) + " (unexpected)\n"
        case None =>
            result = result + "index 2 = nil (out of range, expected)\n"
    }

    // Test CredentialStatus.fromByte
    let statusValid = CredentialStatus.fromByte(TokenStatusListSpec.statusValid)
    let statusInvalid = CredentialStatus.fromByte(TokenStatusListSpec.statusInvalid)
    match (statusValid) {
        case CredentialStatus.Valid => result = result + "status(0x00) = Valid\n"
        case _ => result = result + "status(0x00) = unexpected\n"
    }
    match (statusInvalid) {
        case CredentialStatus.Invalid => result = result + "status(0x01) = Invalid\n"
        case _ => result = result + "status(0x01) = unexpected\n"
    }

    return result
}

/** Format a byte as 2-digit hex string. */
func hexByte(b: UInt8): String {
    let hi = Int64(b >> 4)
    let lo = Int64(b & 0x0Fu8)
    return hexDigit(hi) + hexDigit(lo)
}

func hexDigit(n: Int64): String {
    if (n < 10) { return n.toString() }
    if (n == 10) { return "a" }
    if (n == 11) { return "b" }
    if (n == 12) { return "c" }
    if (n == 13) { return "d" }
    if (n == 14) { return "e" }
    return "f"
}
