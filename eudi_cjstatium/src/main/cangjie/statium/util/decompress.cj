/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * decompress.cj
 *
 * Ported from iOS Sources/Utilities/Decompress.swift and
 * Sources/Extensions/Data+Extenstions.swift (var decompressed: Data).
 *
 * Token Status List `lst` bytes are ZLIB-wrapped (RFC 1950): a 2-byte ZLIB
 * header (0x78 ...), a raw DEFLATE body, and a 4-byte Adler-32 trailer.
 *
 * iOS (Data+Extenstions.swift:decompressedZlibStreaming) handles this by
 *   1. stripping the first 2 bytes (`subdata(in: 2..<count)`), then
 *   2. running Apple's COMPRESSION_ZLIB decoder, which on Apple platforms
 *      actually consumes a RAW DEFLATE stream (no header) — hence the manual
 *      2-byte strip.
 *
 * stdx.compress.zlib only exposes WrapType.DeflateFormat (raw RFC 1951) and
 * GzipFormat — there is NO RFC 1950 ZLIB wrap option. So we mirror iOS
 * exactly: strip the 2-byte ZLIB header, then feed the remaining raw DEFLATE
 * body to DecompressInputStream(wrap: DeflateFormat). The trailing 4-byte
 * Adler-32 checksum is ignored by the raw-DEFLATE decoder (it stops at the
 * DEFLATE end-of-stream marker).
 */
package ohos_app_cangjie_eudi_cjstatium.statium.util

import stdx.compress.zlib.*
import std.io.ByteBuffer
import ohos_app_cangjie_eudi_cjstatium.statium.model.StatusError

/**
 * Decompress a DEFLATE-compressed byte array.
 *
 * Mirrors iOS Decompressible.decompress() -> Data which applies ZLIB/DEFLATE
 * decompression to the status list bytes (after stripping the 2-byte ZLIB
 * header when present). Token Status List spec mandates DEFLATE (RFC 1951).
 *
 * Uses stdx.compress.zlib DecompressInputStream(wrap: DeflateFormat) which
 * handles raw DEFLATE with no wrapping header.
 *
 * Returns empty array on decompression failure (mirrors iOS behavior of
 * returning empty Data on error).
 */
public func decompressDeflate(compressed: Array<UInt8>): Array<UInt8> {
    if (compressed.size == 0) {
        return Array<UInt8>()
    }
    try {
        return decompressDeflateImpl(compressed)
    } catch (_: Exception) {
        return Array<UInt8>()
    }
}

/**
 * Decompress DEFLATE bytes, throwing StatusError on failure.
 */
public func decompressDeflateOrThrow(compressed: Array<UInt8>): Array<UInt8> {
    if (compressed.size == 0) {
        throw StatusError("DecompressEmptyInput")
    }
    try {
        return decompressDeflateImpl(compressed)
    } catch (e: Exception) {
        throw StatusError("DecompressFailed:" + e.message)
    }
}

private func decompressDeflateImpl(compressed: Array<UInt8>): Array<UInt8> {
    // Real Token Status List `lst` bytes are ZLIB-wrapped (RFC 1950): a 2-byte
    // header + raw DEFLATE body + 4-byte Adler-32. iOS strips the 2-byte header.
    // Detect the ZLIB wrapper deterministically — CM nibble == 8 (deflate) and
    // (CMF<<8 | FLG) a multiple of 31 — and strip it; otherwise treat the input
    // as a bare RFC-1951 DEFLATE stream (some producers / test vectors omit the
    // ZLIB wrapper). This matches iOS for real tokens without breaking raw input.
    if (compressed.size > 2 && (UInt64(compressed[0]) & 0x0f) == 8 &&
        (((UInt64(compressed[0]) << 8) | UInt64(compressed[1])) % 31 == 0)) {
        return inflateRaw(compressed[2..compressed.size])
    }
    return inflateRaw(compressed)
}

private func inflateRaw(rawDeflate: Array<UInt8>): Array<UInt8> {
    let buf = ByteBuffer(rawDeflate)
    let stream = DecompressInputStream(buf, wrap: DeflateFormat, bufLen: 4096)
    let chunk = Array<UInt8>(4096, repeat: 0u8)
    var result = Array<UInt8>(0, repeat: 0u8)
    var n = stream.read(chunk)
    while (n > 0) {
        let newResult = Array<UInt8>(result.size + n, repeat: 0u8)
        result.copyTo(newResult, 0, 0, result.size)
        chunk.copyTo(newResult, 0, result.size, n)
        result = newResult
        n = stream.read(chunk)
    }
    stream.close()
    return result
}
