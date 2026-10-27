/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * read_status.cj
 *
 * Ported from iOS Sources/Status/ReadStatus.swift (actor ReadStatus).
 *
 * iOS actor ReadStatus -> Cangjie class (no actor keyword; methods are pure
 * and referentially transparent so concurrency is trivially safe).
 */
package ohos_app_cangjie_eudi_cjstatium.statium.status

import ohos_app_cangjie_eudi_cjstatium.statium.model.*

/**
 * Reads a status value at a given index from a decompressed byte array.
 *
 * The bit width of each status entry is defined by `bitsPerStatus`.
 * This class encapsulates the bit-level addressing logic.
 *
 * Mirrors iOS actor ReadStatus (converted to class).
 */
public class ReadStatus {

    /** Bits used per status entry. */
    public let bitsPerStatus: BitsPerStatus

    /** Decompressed byte array containing status data. */
    public let byteArray: Array<UInt8>

    /**
     * Initialize with bits-per-status and decompressed byte array.
     */
    public init(bitsPerStatus!: BitsPerStatus, byteArray!: Array<UInt8>) {
        this.bitsPerStatus = bitsPerStatus
        this.byteArray = byteArray
    }

    /**
     * Read the status byte at the given logical index.
     *
     * Returns None if the index is negative or out of bounds.
     *
     * Example:
     *   let rs = ReadStatus(bitsPerStatus: BitsPerStatus.Four, byteArray: [0xFF])
     *   rs.readStatus(at: 0)  // Some(0x0F) — lower nibble of 0xFF
     *   rs.readStatus(at: 1)  // Some(0x0F) — upper nibble of 0xFF
     */
    public func readStatus(index: Int64): ?UInt8 {
        if (index < 0) {
            return None
        }

        let (bytePos, bitPos) = byteAndBitPosition(bitsPerStatus, index)

        if (bytePos < 0 || bytePos >= byteArray.size) {
            return None
        }

        let byte = byteArray[bytePos]
        let status = readStatusByte(bitsPerStatus, byte, bitPos)
        return Some(status)
    }
}
