/*
 * unittest_engine.cj - Statium unit tests run inside the HAP entry module.
 *
 * Tests (26 @Test classes covering all public APIs):
 *
 * Bit-read / BitsPerStatus:
 *   1.  ReadStatusOneBitUT            readStatus 1-bit entries
 *   2.  ReadStatusTwoBitUT            readStatus 2-bit entries
 *   3.  ReadStatusFourBitUT           readStatus 4-bit entries
 *   4.  ReadStatusEightBitUT          readStatus 8-bit entries
 *   5.  ReadStatusNegativeIndexUT     negative index -> None
 *   6.  ReadStatusOutOfRangeUT        out-of-range index -> None
 *   7.  ByteAndBitPositionUT          byteAndBitPosition helper
 *   8.  ReadStatusByteUT              readStatusByte helper
 *   9.  BitsPerStatusRawValueUT       BitsPerStatus.rawValue() all cases
 *   10. BitsPerStatusFromRawValueUT   BitsPerStatus.fromRawValue all cases
 *
 * Status enums / models:
 *   11. CredentialStatusFromByteUT    fromByte / toByte
 *   12. StatusListTokenClaimsValidUT  ensureValid — happy path
 *   13. StatusListTokenClaimsExpUT    ensureValid — expired token
 *   14. StatusListTokenClaimsIatUT    ensureValid — future iat
 *   15. StatusListTokenClaimsSubUT    ensureValid — sub mismatch
 *   16. StatusReferenceUT             StatusReference fields
 *   17. StatusListTokenFormatUT       fieldHeaderValue both variants
 *   18. TimeIntervalUnitUT            value() / toSeconds() all cases
 *   19. TokenStatusListSpecUT         spec constants sanity check
 *   20. StatusErrorUT                 StatusError construction / throw
 *   21. StatusListUT                  StatusList field access
 *
 * Util:
 *   22. Base64UrlUT                   encodeBase64Url / decodeBase64Url / fromBase64Url round-trip
 *   23. DecompressUT                  decompressDeflate / decompressDeflateOrThrow round-trip (true zlib)
 *
 * Hard paths (JWT / CWT / end-to-end):
 *   24. JwtParserUT                   parseJwtStatusListClaims with real compact JWT
 *   25. CwtDecoderUT                  decodeCwtStatusListToken with hand-crafted CBOR bytes
 *   26. GetStatusEndToEndUT           GetStatus.getStatus — parse -> decompress -> read (full chain)
 *
 * Smoke test:
 *   27. StatiumDemoSmokeUT            runStatiumDemo() quick sanity
 */
package ohos_app_cangjie_entry

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.*
import stdx.compress.zlib.*
import std.io.ByteBuffer
import kit.PerformanceAnalysisKit.Hilog
import kit.TestKit.AbilityDelegatorRegistry
import kit.TestKit.TestRunner
import kit.AbilityKit.BundleManager
import kit.AbilityKit.BundleFlag
import kit.AbilityKit.Want

import ohos_app_cangjie_eudi_cjstatium.*
import ohos_app_cangjie_eudi_cjstatium.statium.model.*
import ohos_app_cangjie_eudi_cjstatium.statium.spec.*
import ohos_app_cangjie_eudi_cjstatium.statium.status.*
import ohos_app_cangjie_eudi_cjstatium.statium.time.*
import ohos_app_cangjie_eudi_cjstatium.statium.util.*
import ohos_app_cangjie_eudi_cjstatium.statium.network.*
import ohos_app_cangjie_eudi_cjstatium.statium.crypto.*

// ---------------------------------------------------------------------------
// Helper: compress raw bytes with DEFLATE (raw, no zlib header).
// Uses CompressOutputStream(wrap: DeflateFormat) which matches decompressDeflate.
// ---------------------------------------------------------------------------
func compressDeflateHelper(data: Array<UInt8>): Array<UInt8> {
    let buf = ByteBuffer()
    let cs = CompressOutputStream(buf, wrap: DeflateFormat)
    cs.write(data)
    cs.flush()
    cs.close()
    let raw = buf.bytes()
    // Token Status List `lst` is ZLIB (RFC 1950): 2-byte header + raw DEFLATE body.
    // decompressDeflate now strips the leading 2 bytes (iOS parity), so emit a
    // zlib header here to keep the compress/decompress round-trip aligned.
    let wrapped = Array<UInt8>(raw.size + 2, repeat: 0)
    wrapped[0] = 0x78
    wrapped[1] = 0x9c
    raw.copyTo(wrapped, 0, 2, raw.size)
    return wrapped
}

// ---------------------------------------------------------------------------
// Test 1: 1-bit entries
// ---------------------------------------------------------------------------

@Test
class ReadStatusOneBitUT {

    @TestCase
    func testReadStatus_oneBit(): Unit {
        // 0xAA = 10101010b (bit7..bit0), LSB-first status ordering:
        //   idx0=bit0=0, idx1=bit1=1, idx2=bit2=0, idx3=bit3=1
        //   idx4=bit4=0, idx5=bit5=1, idx6=bit6=0, idx7=bit7=1
        let byteArray: Array<UInt8> = [0xAAu8]
        let rs = ReadStatus(bitsPerStatus: BitsPerStatus.One, byteArray: byteArray)

        let r0 = rs.readStatus(0)
        @Expect(r0, Some(0u8))   // bit0 of 0xAA = 0
        let r1 = rs.readStatus(1)
        @Expect(r1, Some(1u8))   // bit1 of 0xAA = 1
        let r6 = rs.readStatus(6)
        @Expect(r6, Some(0u8))   // bit6 of 0xAA = 0 (10101010b: bit6 is second-MSB = 0)
        let r7 = rs.readStatus(7)
        @Expect(r7, Some(1u8))   // bit7 of 0xAA = 1 (MSB = 1)
        let r8 = rs.readStatus(8)
        @Expect(r8, None<UInt8>) // out of range
    }
}

// ---------------------------------------------------------------------------
// Test 2: 2-bit entries
// ---------------------------------------------------------------------------

@Test
class ReadStatusTwoBitUT {

    @TestCase
    func testReadStatus_twoBit(): Unit {
        // 0xE4 = 1110_0100 -> 2-bit pairs (LSB-first): 00, 01, 10, 11
        let byteArray: Array<UInt8> = [0xE4u8]
        let rs = ReadStatus(bitsPerStatus: BitsPerStatus.Two, byteArray: byteArray)

        let r0 = rs.readStatus(0)
        @Expect(r0, Some(0u8))   // bits 1:0 = 00
        let r1 = rs.readStatus(1)
        @Expect(r1, Some(1u8))   // bits 3:2 = 01
        let r2 = rs.readStatus(2)
        @Expect(r2, Some(2u8))   // bits 5:4 = 10
        let r3 = rs.readStatus(3)
        @Expect(r3, Some(3u8))   // bits 7:6 = 11
        let r4 = rs.readStatus(4)
        @Expect(r4, None<UInt8>) // out of range
    }
}

// ---------------------------------------------------------------------------
// Test 3: 4-bit entries
// ---------------------------------------------------------------------------

@Test
class ReadStatusFourBitUT {

    @TestCase
    func testReadStatus_fourBit(): Unit {
        // 0xFF = 1111_1111 -> 4-bit pairs: 0x0F, 0x0F
        let byteArray: Array<UInt8> = [0xFFu8]
        let rs = ReadStatus(bitsPerStatus: BitsPerStatus.Four, byteArray: byteArray)

        let r0 = rs.readStatus(0)
        @Expect(r0, Some(0x0Fu8))
        let r1 = rs.readStatus(1)
        @Expect(r1, Some(0x0Fu8))
        let r2 = rs.readStatus(2)
        @Expect(r2, None<UInt8>) // out of range for 1 byte / 4-bit
    }
}

// ---------------------------------------------------------------------------
// Test 4: 8-bit entries
// ---------------------------------------------------------------------------

@Test
class ReadStatusEightBitUT {

    @TestCase
    func testReadStatus_eightBit(): Unit {
        let byteArray: Array<UInt8> = [0x00u8, 0x01u8, 0x02u8]
        let rs = ReadStatus(bitsPerStatus: BitsPerStatus.Eight, byteArray: byteArray)

        @Expect(rs.readStatus(0), Some(0x00u8))
        @Expect(rs.readStatus(1), Some(0x01u8))
        @Expect(rs.readStatus(2), Some(0x02u8))
        @Expect(rs.readStatus(3), None<UInt8>)
    }
}

// ---------------------------------------------------------------------------
// Test 5: negative index
// ---------------------------------------------------------------------------

@Test
class ReadStatusNegativeIndexUT {

    @TestCase
    func testReadStatus_negativeIndex(): Unit {
        let byteArray: Array<UInt8> = [0xFFu8]
        let rs = ReadStatus(bitsPerStatus: BitsPerStatus.Eight, byteArray: byteArray)
        @Expect(rs.readStatus(-1), None<UInt8>)
        @Expect(rs.readStatus(-100), None<UInt8>)
    }
}

// ---------------------------------------------------------------------------
// Test 6: out-of-range (zero-byte array)
// ---------------------------------------------------------------------------

@Test
class ReadStatusOutOfRangeUT {

    @TestCase
    func testReadStatus_emptyArray(): Unit {
        let byteArray: Array<UInt8> = []
        let rs = ReadStatus(bitsPerStatus: BitsPerStatus.One, byteArray: byteArray)
        @Expect(rs.readStatus(0), None<UInt8>)
    }

    @TestCase
    func testReadStatus_multiByteOutOfRange(): Unit {
        // 2 bytes / 1-bit = 16 entries
        let byteArray: Array<UInt8> = [0xFFu8, 0xFFu8]
        let rs = ReadStatus(bitsPerStatus: BitsPerStatus.One, byteArray: byteArray)
        @Expect(rs.readStatus(15), Some(1u8))
        @Expect(rs.readStatus(16), None<UInt8>)
    }
}

// ---------------------------------------------------------------------------
// Test 7: byteAndBitPosition helper
// ---------------------------------------------------------------------------

@Test
class ByteAndBitPositionUT {

    @TestCase
    func testByteAndBitPosition_oneBit(): Unit {
        // 1-bit: statusesPerByte=8 -> index 9 => byte=1, bit=1
        let (b, p) = byteAndBitPosition(BitsPerStatus.One, 9)
        @Expect(b, 1i64)
        @Expect(p, 1i64)
    }

    @TestCase
    func testByteAndBitPosition_twoBit(): Unit {
        // 2-bit: statusesPerByte=4 -> index 5 => byte=1, bit=2
        let (b, p) = byteAndBitPosition(BitsPerStatus.Two, 5)
        @Expect(b, 1i64)
        @Expect(p, 2i64)
    }

    @TestCase
    func testByteAndBitPosition_fourBit(): Unit {
        // 4-bit: statusesPerByte=2 -> index 3 => byte=1, bit=4
        let (b, p) = byteAndBitPosition(BitsPerStatus.Four, 3)
        @Expect(b, 1i64)
        @Expect(p, 4i64)
    }

    @TestCase
    func testByteAndBitPosition_eightBit(): Unit {
        // 8-bit: statusesPerByte=1 -> index 7 => byte=7, bit=0
        let (b, p) = byteAndBitPosition(BitsPerStatus.Eight, 7)
        @Expect(b, 7i64)
        @Expect(p, 0i64)
    }
}

// ---------------------------------------------------------------------------
// Test 8: readStatusByte helper
// ---------------------------------------------------------------------------

@Test
class ReadStatusByteUT {

    @TestCase
    func testReadStatusByte_oneBitAtZero(): Unit {
        // 0xAA = 1010_1010; bit0 = 0
        let v = readStatusByte(BitsPerStatus.One, 0xAAu8, 0)
        @Expect(v, 0u8)
    }

    @TestCase
    func testReadStatusByte_oneBitAtOne(): Unit {
        // bit1 of 0xAA = 1
        let v = readStatusByte(BitsPerStatus.One, 0xAAu8, 1)
        @Expect(v, 1u8)
    }

    @TestCase
    func testReadStatusByte_twoBitAtFour(): Unit {
        // 0xE4 = 1110_0100; bits[5:4] = 10 = 2
        let v = readStatusByte(BitsPerStatus.Two, 0xE4u8, 4)
        @Expect(v, 2u8)
    }

    @TestCase
    func testReadStatusByte_eightBit(): Unit {
        // 8-bit at position 0: returns the whole byte
        let v = readStatusByte(BitsPerStatus.Eight, 0xABu8, 0)
        @Expect(v, 0xABu8)
    }
}

// ---------------------------------------------------------------------------
// Test 9: BitsPerStatus.rawValue()
// ---------------------------------------------------------------------------

@Test
class BitsPerStatusRawValueUT {

    @TestCase
    func testRawValues(): Unit {
        @Expect(BitsPerStatus.One.rawValue(),   1i64)
        @Expect(BitsPerStatus.Two.rawValue(),   2i64)
        @Expect(BitsPerStatus.Four.rawValue(),  4i64)
        @Expect(BitsPerStatus.Eight.rawValue(), 8i64)
    }
}

// ---------------------------------------------------------------------------
// Test 10: BitsPerStatus.fromRawValue()
// ---------------------------------------------------------------------------

@Test
class BitsPerStatusFromRawValueUT {

    @TestCase
    func testFromRawValue_valid(): Unit {
        match (BitsPerStatus.fromRawValue(1)) {
            case Some(BitsPerStatus.One) => ()
            case _ => throw Exception("expected One")
        }
        match (BitsPerStatus.fromRawValue(2)) {
            case Some(BitsPerStatus.Two) => ()
            case _ => throw Exception("expected Two")
        }
        match (BitsPerStatus.fromRawValue(4)) {
            case Some(BitsPerStatus.Four) => ()
            case _ => throw Exception("expected Four")
        }
        match (BitsPerStatus.fromRawValue(8)) {
            case Some(BitsPerStatus.Eight) => ()
            case _ => throw Exception("expected Eight")
        }
    }

    @TestCase
    func testFromRawValue_invalid(): Unit {
        match (BitsPerStatus.fromRawValue(0)) {
            case None => ()
            case Some(_) => throw Exception("expected None for fromRawValue(0)")
        }
        match (BitsPerStatus.fromRawValue(3)) {
            case None => ()
            case Some(_) => throw Exception("expected None for fromRawValue(3)")
        }
        match (BitsPerStatus.fromRawValue(16)) {
            case None => ()
            case Some(_) => throw Exception("expected None for fromRawValue(16)")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 11: CredentialStatus.fromByte / toByte
// ---------------------------------------------------------------------------

@Test
class CredentialStatusFromByteUT {

    @TestCase
    func testCredentialStatus_fromByte(): Unit {
        match (CredentialStatus.fromByte(0x00u8)) {
            case CredentialStatus.Valid => ()
            case _ => throw Exception("expected Valid")
        }
        match (CredentialStatus.fromByte(0x01u8)) {
            case CredentialStatus.Invalid => ()
            case _ => throw Exception("expected Invalid")
        }
        match (CredentialStatus.fromByte(0x02u8)) {
            case CredentialStatus.Suspended => ()
            case _ => throw Exception("expected Suspended")
        }
        match (CredentialStatus.fromByte(0x03u8)) {
            case CredentialStatus.ApplicationSpecific(_) => ()
            case _ => throw Exception("expected ApplicationSpecific(0x03)")
        }
        match (CredentialStatus.fromByte(0x0Bu8)) {
            case CredentialStatus.ApplicationSpecific(_) => ()
            case _ => throw Exception("expected ApplicationSpecific(0x0B)")
        }
        match (CredentialStatus.fromByte(0x0Fu8)) {
            case CredentialStatus.ApplicationSpecific(_) => ()
            case _ => throw Exception("expected ApplicationSpecific(0x0F)")
        }
        match (CredentialStatus.fromByte(0xFFu8)) {
            case CredentialStatus.Reserved(_) => ()
            case _ => throw Exception("expected Reserved")
        }
    }

    @TestCase
    func testCredentialStatus_toByte(): Unit {
        @Expect(CredentialStatus.Valid.toByte(), 0x00u8)
        @Expect(CredentialStatus.Invalid.toByte(), 0x01u8)
        @Expect(CredentialStatus.Suspended.toByte(), 0x02u8)
        @Expect(CredentialStatus.ApplicationSpecific(0x03u8).toByte(), 0x03u8)
        @Expect(CredentialStatus.Reserved(0xFFu8).toByte(), 0xFFu8)
    }

    @TestCase
    func testCredentialStatus_roundTrip(): Unit {
        for (raw in [0x00u8, 0x01u8, 0x02u8, 0x03u8, 0x0Bu8, 0x0Fu8, 0x10u8, 0xFFu8]) {
            let status = CredentialStatus.fromByte(raw)
            @Expect(status.toByte(), raw)
        }
    }
}

// ---------------------------------------------------------------------------
// Test 12: StatusListTokenClaims.ensureValid — happy path
// ---------------------------------------------------------------------------

@Test
class StatusListTokenClaimsValidUT {

    @TestCase
    func testEnsureValid_happy(): Unit {
        let sl = StatusList(bitsPerStatus: BitsPerStatus.One, compressedList: "WwUA", aggregationUri: None<String>)
        let claims = StatusListTokenClaims(
            subject: "https://example.com/status",
            issuedAt: 1000.0,
            expirationTime: Some(9999999999.0),
            timeToLive: None<Float64>,
            statusList: sl
        )
        // nowSecs=2000, clockSkew=5: iat=1000 < 2000+5 (ok), exp=9999... > 2000-5 (ok), sub matches
        let result = claims.ensureValid("https://example.com/status", 2000.0, 5.0)
        @Expect(result.subject, "https://example.com/status")
        @Expect(result.issuedAt, 1000.0)
    }
}

// ---------------------------------------------------------------------------
// Test 13: StatusListTokenClaims.ensureValid — expired token
// ---------------------------------------------------------------------------

@Test
class StatusListTokenClaimsExpUT {

    @TestCase
    func testEnsureValid_expired(): Unit {
        let sl = StatusList(bitsPerStatus: BitsPerStatus.One, compressedList: "WwUA", aggregationUri: None<String>)
        let claims = StatusListTokenClaims(
            subject: "https://example.com/status",
            issuedAt: 1000.0,
            expirationTime: Some(500.0), // exp=500 < now=2000 => expired
            timeToLive: None<Float64>,
            statusList: sl
        )
        var threw = false
        try {
            let _ = claims.ensureValid("https://example.com/status", 2000.0, 0.0)
        } catch (e: StatusError) {
            threw = true
            if (!e.message.contains("Expired")) {
                throw Exception("expected 'Expired' in message, got: " + e.message)
            }
        }
        if (!threw) {
            throw Exception("expected StatusError for expired token")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 14: StatusListTokenClaims.ensureValid — future iat
// ---------------------------------------------------------------------------

@Test
class StatusListTokenClaimsIatUT {

    @TestCase
    func testEnsureValid_futureIat(): Unit {
        let sl = StatusList(bitsPerStatus: BitsPerStatus.One, compressedList: "WwUA", aggregationUri: None<String>)
        let claims = StatusListTokenClaims(
            subject: "https://example.com/status",
            issuedAt: 9999999.0, // iat far in future
            expirationTime: None<Float64>,
            timeToLive: None<Float64>,
            statusList: sl
        )
        var threw = false
        try {
            let _ = claims.ensureValid("https://example.com/status", 1000.0, 0.0)
        } catch (e: StatusError) {
            threw = true
            if (!e.message.contains("InvalidIssueDate")) {
                throw Exception("expected 'InvalidIssueDate', got: " + e.message)
            }
        }
        if (!threw) {
            throw Exception("expected StatusError for future iat")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 15: StatusListTokenClaims.ensureValid — subject mismatch
// ---------------------------------------------------------------------------

@Test
class StatusListTokenClaimsSubUT {

    @TestCase
    func testEnsureValid_subjectMismatch(): Unit {
        let sl = StatusList(bitsPerStatus: BitsPerStatus.One, compressedList: "WwUA", aggregationUri: None<String>)
        let claims = StatusListTokenClaims(
            subject: "https://example.com/status",
            issuedAt: 1000.0,
            expirationTime: None<Float64>,
            timeToLive: None<Float64>,
            statusList: sl
        )
        var threw = false
        try {
            let _ = claims.ensureValid("https://other.example.com/status", 2000.0, 0.0)
        } catch (e: StatusError) {
            threw = true
            if (!e.message.contains("BadSubject")) {
                throw Exception("expected 'BadSubject', got: " + e.message)
            }
        }
        if (!threw) {
            throw Exception("expected StatusError for subject mismatch")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 16: StatusReference
// ---------------------------------------------------------------------------

@Test
class StatusReferenceUT {

    @TestCase
    func testStatusReference_fields(): Unit {
        let ref = StatusReference(idx: 42i64, uri: "https://example.com/status-list")
        @Expect(ref.idx, 42i64)
        @Expect(ref.uri, "https://example.com/status-list")
    }
}

// ---------------------------------------------------------------------------
// Test 17: StatusListTokenFormat.fieldHeaderValue
// ---------------------------------------------------------------------------

@Test
class StatusListTokenFormatUT {

    @TestCase
    func testJwtHeaderValue(): Unit {
        let v = StatusListTokenFormat.Jwt.fieldHeaderValue()
        @Expect(v, "application/statuslist+jwt")
    }

    @TestCase
    func testCwtHeaderValue(): Unit {
        let v = StatusListTokenFormat.Cwt.fieldHeaderValue()
        @Expect(v, "application/statuslist+cwt")
    }
}

// ---------------------------------------------------------------------------
// Test 18: TimeIntervalUnit
// ---------------------------------------------------------------------------

@Test
class TimeIntervalUnitUT {

    @TestCase
    func testValue(): Unit {
        @Expect(TimeIntervalUnit.Seconds.value(), 1.0)
        @Expect(TimeIntervalUnit.Minutes.value(), 60.0)
        @Expect(TimeIntervalUnit.Hours.value(), 3600.0)
        @Expect(TimeIntervalUnit.Days.value(), 86400.0)
        @Expect(TimeIntervalUnit.Weeks.value(), 604800.0)
    }

    @TestCase
    func testToSeconds(): Unit {
        @Expect(TimeIntervalUnit.Seconds.toSeconds(10.0), 10.0)
        @Expect(TimeIntervalUnit.Minutes.toSeconds(2.0), 120.0)
        @Expect(TimeIntervalUnit.Hours.toSeconds(1.0), 3600.0)
        @Expect(TimeIntervalUnit.Days.toSeconds(1.0), 86400.0)
        @Expect(TimeIntervalUnit.Weeks.toSeconds(1.0), 604800.0)
    }
}

// ---------------------------------------------------------------------------
// Test 19: TokenStatusListSpec constants
// ---------------------------------------------------------------------------

@Test
class TokenStatusListSpecUT {

    @TestCase
    func testStatusConstants(): Unit {
        @Expect(TokenStatusListSpec.statusValid, 0x00u8)
        @Expect(TokenStatusListSpec.statusInvalid, 0x01u8)
        @Expect(TokenStatusListSpec.statusSuspended, 0x02u8)
        @Expect(TokenStatusListSpec.statusApplicationSpecific, 0x03u8)
    }

    @TestCase
    func testMediaTypes(): Unit {
        @Expect(TokenStatusListSpec.mediaSubtypeStatusListJWT, "statuslist+jwt")
        @Expect(TokenStatusListSpec.mediaTypeApplicationStatusListJWT, "application/statuslist+jwt")
        @Expect(TokenStatusListSpec.mediaSubtypeStatusListCWT, "statuslist+cwt")
        @Expect(TokenStatusListSpec.mediaTypeApplicationStatusListCWT, "application/statuslist+cwt")
    }

    @TestCase
    func testFieldNames(): Unit {
        @Expect(TokenStatusListSpec.statusList, "status_list")
        @Expect(TokenStatusListSpec.bits, "bits")
        @Expect(TokenStatusListSpec.list, "lst")
        @Expect(TokenStatusListSpec.idx, "idx")
        @Expect(TokenStatusListSpec.uri, "uri")
    }
}

// ---------------------------------------------------------------------------
// Test 20: StatusError construction and throwing
// ---------------------------------------------------------------------------

@Test
class StatusErrorUT {

    @TestCase
    func testStatusError_construction(): Unit {
        let e = StatusError("TestMessage")
        if (!e.message.contains("TestMessage")) {
            throw Exception("StatusError message mismatch, got: " + e.message)
        }
    }

    @TestCase
    func testStatusError_throw(): Unit {
        var caught = false
        try {
            throw StatusError("thrownError")
        } catch (e: StatusError) {
            caught = true
            if (!e.message.contains("thrownError")) {
                throw Exception("wrong message: " + e.message)
            }
        }
        if (!caught) {
            throw Exception("StatusError was not caught")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 21: StatusList field access
// ---------------------------------------------------------------------------

@Test
class StatusListUT {

    @TestCase
    func testStatusList_fields(): Unit {
        let sl = StatusList(
            bitsPerStatus: BitsPerStatus.Two,
            compressedList: "WwUA",
            aggregationUri: Some("https://example.com/agg")
        )
        @Expect(sl.bitsPerStatus.rawValue(), 2i64)
        @Expect(sl.compressedList, "WwUA")
        match (sl.aggregationUri) {
            case Some(u) => @Expect(u, "https://example.com/agg")
            case None => throw Exception("expected aggregationUri")
        }
    }

    @TestCase
    func testStatusList_noAggregation(): Unit {
        let sl = StatusList(
            bitsPerStatus: BitsPerStatus.One,
            compressedList: "abc",
            aggregationUri: None<String>
        )
        match (sl.aggregationUri) {
            case None => ()
            case Some(_) => throw Exception("expected None aggregationUri")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 22: base64url round-trip
// ---------------------------------------------------------------------------

@Test
class Base64UrlUT {

    @TestCase
    func testEncodeDecodeRoundTrip(): Unit {
        // Known vector: [0x00, 0x01, 0x02, 0xFF, 0xFE] -> base64url "AAEC__8"
        // (no padding, url-safe)
        let original: Array<UInt8> = [0x00u8, 0x01u8, 0x02u8, 0xFFu8, 0xFEu8]
        let encoded = encodeBase64Url(original)
        let decoded = decodeBase64Url(encoded)
        if (decoded.size != original.size) {
            throw Exception("size mismatch after round-trip: " + decoded.size.toString() + " vs " + original.size.toString())
        }
        var i: Int64 = 0
        while (i < original.size) {
            if (decoded[i] != original[i]) {
                throw Exception("byte mismatch at index " + i.toString())
            }
            i = i + 1
        }
    }

    @TestCase
    func testFromBase64Url_valid(): Unit {
        // "WwUA" = [0x5B, 0x05, 0x00] (DEFLATE compressed [0xAA])
        let result = fromBase64Url("WwUA")
        match (result) {
            case Some(bytes) =>
                @Expect(bytes.size, 3i64)
                @Expect(bytes[0], 0x5Bu8)
                @Expect(bytes[1], 0x05u8)
                @Expect(bytes[2], 0x00u8)
            case None => throw Exception("fromBase64Url returned None for valid input")
        }
    }

    @TestCase
    func testFromBase64Url_empty(): Unit {
        // "" decodes to empty array (not an error in base64url)
        let result = fromBase64Url("")
        match (result) {
            case Some(bytes) => @Expect(bytes.size, 0i64)
            case None => ()  // acceptable either way
        }
    }

    @TestCase
    func testDecodeBase64Url_invalid(): Unit {
        var threw = false
        try {
            let _ = decodeBase64Url("!!!not-valid!!!")
        } catch (e: StatusError) {
            threw = true
        }
        if (!threw) {
            throw Exception("expected StatusError for invalid base64url input")
        }
    }

    @TestCase
    func testEncodeDecodeEmptyBytes(): Unit {
        let empty: Array<UInt8> = []
        let encoded = encodeBase64Url(empty)
        let decoded = decodeBase64Url(encoded)
        @Expect(decoded.size, 0i64)
    }
}

// ---------------------------------------------------------------------------
// Test 23: Decompress — true DEFLATE round-trip
// ---------------------------------------------------------------------------

@Test
class DecompressUT {

    @TestCase
    func testDecompressDeflate_roundTrip(): Unit {
        // Compress [0xAA, 0xBB, 0xCC] with CompressOutputStream(DeflateFormat)
        // then decompress with decompressDeflate.  Must recover exact bytes.
        let original: Array<UInt8> = [0xAAu8, 0xBBu8, 0xCCu8]
        let compressed = compressDeflateHelper(original)
        if (compressed.size == 0) {
            throw Exception("compression produced empty output")
        }
        let recovered = decompressDeflate(compressed)
        if (recovered.size != original.size) {
            throw Exception("size mismatch: " + recovered.size.toString() + " vs " + original.size.toString())
        }
        var i: Int64 = 0
        while (i < original.size) {
            if (recovered[i] != original[i]) {
                throw Exception("byte mismatch at " + i.toString() + ": got " + recovered[i].toString() + " want " + original[i].toString())
            }
            i = i + 1
        }
    }

    @TestCase
    func testDecompressDeflate_knownVector(): Unit {
        // Pre-computed: DEFLATE compress [0xAA] = [0x5B, 0x05, 0x00]
        // Verified by Python: zlib.compress(b'\xaa',6)[2:-4] == b'\x5b\x05\x00'
        let compressed: Array<UInt8> = [0x5Bu8, 0x05u8, 0x00u8]
        let recovered = decompressDeflate(compressed)
        @Expect(recovered.size, 1i64)
        @Expect(recovered[0], 0xAAu8)
    }

    @TestCase
    func testDecompressDeflate_emptyInput(): Unit {
        // Empty input -> returns empty (not a throw in the soft version)
        let result = decompressDeflate([])
        @Expect(result.size, 0i64)
    }

    @TestCase
    func testDecompressDeflateOrThrow_roundTrip(): Unit {
        let original: Array<UInt8> = [0x01u8, 0x02u8, 0x03u8, 0x04u8]
        let compressed = compressDeflateHelper(original)
        let recovered = decompressDeflateOrThrow(compressed)
        if (recovered.size != original.size) {
            throw Exception("size mismatch")
        }
        var i: Int64 = 0
        while (i < original.size) {
            if (recovered[i] != original[i]) {
                throw Exception("byte mismatch at " + i.toString())
            }
            i = i + 1
        }
    }

    @TestCase
    func testDecompressDeflateOrThrow_emptyThrows(): Unit {
        var threw = false
        try {
            let _ = decompressDeflateOrThrow([])
        } catch (e: StatusError) {
            threw = true
            if (!e.message.contains("DecompressEmptyInput")) {
                throw Exception("expected 'DecompressEmptyInput', got: " + e.message)
            }
        }
        if (!threw) {
            throw Exception("expected StatusError for empty input")
        }
    }

    @TestCase
    func testDecompressDeflateOrThrow_invalidThrows(): Unit {
        // Garbage bytes that are not valid DEFLATE
        let garbage: Array<UInt8> = [0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8]
        var threw = false
        try {
            let _ = decompressDeflateOrThrow(garbage)
        } catch (e: StatusError) {
            threw = true
        }
        if (!threw) {
            throw Exception("expected StatusError for invalid DEFLATE input")
        }
    }

    @TestCase
    func testDecompressDeflate_largerPayload(): Unit {
        // Compress 100 bytes and verify round-trip
        let original = Array<UInt8>(100, repeat: 0x42u8)
        let compressed = compressDeflateHelper(original)
        let recovered = decompressDeflate(compressed)
        @Expect(recovered.size, 100i64)
        var i: Int64 = 0
        while (i < 100) {
            @Expect(recovered[i], 0x42u8)
            i = i + 1
        }
    }
}

// ---------------------------------------------------------------------------
// Test 24: JWT parser — parseJwtStatusListClaims
//
// Test vector (pre-computed):
//   Header : {"alg":"ES256","typ":"statuslist+jwt"}
//   Payload: {"sub":"https://example.com/status","iat":1700000000,
//              "status_list":{"bits":1,"lst":"WwUA"}}
//   Sig    : [0xDE,0xAD,0xBE,0xEF] (dummy — we skip sig verification)
//
//   compact JWT = eyJhbGciOiJFUzI1NiIsInR5cCI6InN0YXR1c2xpc3Qrand0In0.
//                 eyJzdWIiOiJodHRwczovL2V4YW1wbGUuY29tL3N0YXR1cyIsImlh
//                 dCI6MTcwMDAwMDAwMCwic3RhdHVzX2xpc3QiOnsiYml0cyI6MSwi
//                 bHN0IjoiV3dVQSJ9fQ.3q2-7w
//
// "lst":"WwUA" = base64url([0x5B,0x05,0x00]) = DEFLATE-compressed [0xAA]
// ---------------------------------------------------------------------------

@Test
class JwtParserUT {

    // Full compact JWT string (generated by Python reference above).
    // Sub-claim = uri, so sub validation passes.
    // iat=1700000000, nowSecs=1700000100, clockSkew=60 => iat ok, no exp => ok.
    let jwtCompact: String =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6InN0YXR1c2xpc3Qrand0In0." +
        "eyJzdWIiOiJodHRwczovL2V4YW1wbGUuY29tL3N0YXR1cyIsImlhdCI6MTcwMDAwMDAwMCwic3RhdHVzX2xpc3QiOnsiYml0cyI6MSwibHN0IjoiV3dVQSJ9fQ." +
        "3q2-7w"

    @TestCase
    func testParseJwtStatusListClaims_happy(): Unit {
        let claims = parseJwtStatusListClaims(
            jwtCompact,
            "https://example.com/status",
            1700000100.0,  // nowSecs: 100s after iat
            60.0           // clockSkew
        )
        @Expect(claims.subject, "https://example.com/status")
        @Expect(claims.issuedAt, 1700000000.0)
        match (claims.expirationTime) {
            case None => ()   // no exp in this JWT
            case Some(_) => throw Exception("unexpected expirationTime")
        }
        @Expect(claims.statusList.bitsPerStatus.rawValue(), 1i64)
        @Expect(claims.statusList.compressedList, "WwUA")
    }

    @TestCase
    func testParseJwtStatusListClaims_wrongTyp(): Unit {
        // Replace typ with something else — should throw BadJwtHeader
        let badHdr = "eyJhbGciOiJFUzI1NiIsInR5cCI6Indyb25nIn0" // {"alg":"ES256","typ":"wrong"}
        let badJwt = badHdr + "." +
            "eyJzdWIiOiJodHRwczovL2V4YW1wbGUuY29tL3N0YXR1cyIsImlhdCI6MTcwMDAwMDAwMCwic3RhdHVzX2xpc3QiOnsiYml0cyI6MSwibHN0IjoiV3dVQSJ9fQ." +
            "3q2-7w"
        var threw = false
        try {
            let _ = parseJwtStatusListClaims(badJwt, "https://example.com/status", 1700000100.0, 60.0)
        } catch (e: StatusError) {
            threw = true
            if (!e.message.contains("BadJwtHeader")) {
                throw Exception("expected 'BadJwtHeader', got: " + e.message)
            }
        }
        if (!threw) {
            throw Exception("expected StatusError for wrong typ")
        }
    }

    @TestCase
    func testParseJwtStatusListClaims_notThreeParts(): Unit {
        var threw = false
        try {
            let _ = parseJwtStatusListClaims("onlyonepart", "https://example.com/status", 1700000100.0, 60.0)
        } catch (e: StatusError) {
            threw = true
            if (!e.message.contains("InvalidJWT")) {
                throw Exception("expected 'InvalidJWT', got: " + e.message)
            }
        }
        if (!threw) {
            throw Exception("expected StatusError for non-three-part JWT")
        }
    }

    @TestCase
    func testParseJwtStatusListClaims_subjectMismatch(): Unit {
        var threw = false
        try {
            let _ = parseJwtStatusListClaims(
                jwtCompact,
                "https://DIFFERENT.com/status", // wrong uri
                1700000100.0,
                60.0
            )
        } catch (e: StatusError) {
            threw = true
            if (!e.message.contains("BadSubject")) {
                throw Exception("expected 'BadSubject', got: " + e.message)
            }
        }
        if (!threw) {
            throw Exception("expected StatusError for sub mismatch")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 25: CWT decoder — decodeCwtStatusListToken
//
// Test vector (96 bytes, pre-computed by Python):
//   COSE_Sign1 (tag 18) wrapping:
//     [0] protected header bstr: {16: "application/statuslist+cwt"}
//     [1] unprotected header:  {}
//     [2] payload bstr: {2: "https://example.com/status", 6: 1700000000,
//                        65533: {"bits": 1, "lst": bstr([0x5B,0x05,0x00])}}
//     [3] signature bstr: [0xDE, 0xAD, 0xBE, 0xEF]
//
//   The decodeCwtStatusListToken function does NOT verify the signature;
//   it only decodes and validates iat/exp/sub claims.
// ---------------------------------------------------------------------------

@Test
class CwtDecoderUT {

    let cwtToken: Array<UInt8> = [
        0xD2u8, 0x84u8, 0x58u8, 0x1Eu8, 0xA1u8, 0x10u8, 0x78u8, 0x1Au8, 0x61u8, 0x70u8, 0x70u8, 0x6Cu8,
        0x69u8, 0x63u8, 0x61u8, 0x74u8, 0x69u8, 0x6Fu8, 0x6Eu8, 0x2Fu8, 0x73u8, 0x74u8, 0x61u8, 0x74u8,
        0x75u8, 0x73u8, 0x6Cu8, 0x69u8, 0x73u8, 0x74u8, 0x2Bu8, 0x63u8, 0x77u8, 0x74u8, 0xA0u8, 0x58u8,
        0x36u8, 0xA3u8, 0x02u8, 0x78u8, 0x1Au8, 0x68u8, 0x74u8, 0x74u8, 0x70u8, 0x73u8, 0x3Au8, 0x2Fu8,
        0x2Fu8, 0x65u8, 0x78u8, 0x61u8, 0x6Du8, 0x70u8, 0x6Cu8, 0x65u8, 0x2Eu8, 0x63u8, 0x6Fu8, 0x6Du8,
        0x2Fu8, 0x73u8, 0x74u8, 0x61u8, 0x74u8, 0x75u8, 0x73u8, 0x06u8, 0x1Au8, 0x65u8, 0x53u8, 0xF1u8,
        0x00u8, 0x19u8, 0xFFu8, 0xFDu8, 0xA2u8, 0x64u8, 0x62u8, 0x69u8, 0x74u8, 0x73u8, 0x01u8, 0x63u8,
        0x6Cu8, 0x73u8, 0x74u8, 0x43u8, 0x5Bu8, 0x05u8, 0x00u8, 0x44u8, 0xDEu8, 0xADu8, 0xBEu8, 0xEFu8
    ]

    @TestCase
    func testDecodeCwtStatusListToken_happy(): Unit {
        // fetchedFrom = Some(sub) so subject validation passes
        // nowSecs = 1700000100 (100s after iat=1700000000), no exp => ok
        let claims = decodeCwtStatusListToken(
            cwtToken,
            Some("https://example.com/status"),
            1700000100.0,
            60.0
        )
        @Expect(claims.subject, "https://example.com/status")
        @Expect(claims.issuedAt, 1700000000.0)
        match (claims.expirationTime) {
            case None => ()
            case Some(_) => throw Exception("unexpected expirationTime")
        }
        // status_list: bits=1, lst=base64url([0x5B,0x05,0x00])="WwUA"
        @Expect(claims.statusList.bitsPerStatus.rawValue(), 1i64)
        @Expect(claims.statusList.compressedList, "WwUA")
    }

    @TestCase
    func testDecodeCwtStatusListToken_noFetchedFrom(): Unit {
        // fetchedFrom=None skips subject validation — should succeed
        let claims = decodeCwtStatusListToken(
            cwtToken,
            None<String>,
            1700000100.0,
            60.0
        )
        @Expect(claims.subject, "https://example.com/status")
    }

    @TestCase
    func testDecodeCwtStatusListToken_subjectMismatch(): Unit {
        var threw = false
        try {
            let _ = decodeCwtStatusListToken(
                cwtToken,
                Some("https://WRONG.com"),
                1700000100.0,
                60.0
            )
        } catch (e: StatusError) {
            threw = true
            if (!e.message.contains("CwtSubjectMismatch") && !e.message.contains("BadSubject")) {
                throw Exception("expected CwtSubjectMismatch, got: " + e.message)
            }
        }
        if (!threw) {
            throw Exception("expected StatusError for sub mismatch")
        }
    }

    @TestCase
    func testDecodeCwtStatusListToken_emptyInput(): Unit {
        var threw = false
        try {
            let _ = decodeCwtStatusListToken([], None<String>, 1700000100.0, 60.0)
        } catch (e: StatusError) {
            threw = true
        } catch (e: Exception) {
            threw = true
        }
        if (!threw) {
            throw Exception("expected error for empty input")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 26: GetStatus end-to-end (parse -> decompress -> bit-read full chain)
//
// Strategy: We construct a StatusListTokenClaims object directly with a known
// compressedList (base64url of [0x5B,0x05,0x00] = DEFLATE compressed [0xAA]).
// We inject it via a FetchClaimsHandler closure so no network is involved.
//
// [0xAA] = 1010_1010 with 1-bit entries => statuses at indexes 0..7:
//   idx 0 -> 0 (Valid)
//   idx 1 -> 1 (Invalid)
//   idx 2 -> 0 (Valid)
//   idx 3 -> 1 (Invalid)
// ---------------------------------------------------------------------------

@Test
class GetStatusEndToEndUT {

    // Build a StatusListTokenClaims for 1-bit status list over [0xAA]
    // compressedList = base64url([0x5B,0x05,0x00]) = "WwUA"
    func buildTestClaims(): StatusListTokenClaims {
        let sl = StatusList(
            bitsPerStatus: BitsPerStatus.One,
            compressedList: "WwUA",  // base64url([0x5B,0x05,0x00]) = DEFLATE compressed [0xAA]
            aggregationUri: None<String>
        )
        return StatusListTokenClaims(
            subject: "https://example.com/status",
            issuedAt: 1700000000.0,
            expirationTime: None<Float64>,
            timeToLive: None<Float64>,
            statusList: sl
        )
    }

    @TestCase
    func testGetStatus_index0_isValid(): Unit {
        let gs = GetStatus()
        let testClaims = buildTestClaims()
        // fetchClaims ignores network, returns prebuilt claims
        let result = gs.getStatus(
            0i64,
            "https://example.com/status",
            StatusListTokenFormat.Jwt,
            { _fmt: StatusListTokenFormat, _url: String, _nowSecs: Float64, _clockSkew: Float64 =>
                testClaims
            },
            1700000100.0,
            60.0
        )
        match (result) {
            case CredentialStatus.Valid => ()
            case _ => throw Exception("expected Valid at index 0, got: " + result.toByte().toString())
        }
    }

    @TestCase
    func testGetStatus_index1_isInvalid(): Unit {
        let gs = GetStatus()
        let testClaims = buildTestClaims()
        let result = gs.getStatus(
            1i64,
            "https://example.com/status",
            StatusListTokenFormat.Jwt,
            { _fmt: StatusListTokenFormat, _url: String, _nowSecs: Float64, _clockSkew: Float64 =>
                testClaims
            },
            1700000100.0,
            60.0
        )
        match (result) {
            case CredentialStatus.Invalid => ()
            case _ => throw Exception("expected Invalid at index 1, got: " + result.toByte().toString())
        }
    }

    @TestCase
    func testGetStatus_viaReference(): Unit {
        // Test the StatusReference overload
        let gs = GetStatus()
        let testClaims = buildTestClaims()
        let ref = StatusReference(idx: 3i64, uri: "https://example.com/status")
        let result = gs.getStatus(
            ref,
            StatusListTokenFormat.Jwt,
            { _fmt: StatusListTokenFormat, _url: String, _nowSecs: Float64, _clockSkew: Float64 =>
                testClaims
            },
            1700000100.0,
            60.0
        )
        // [0xAA] bit3 = 1 => Invalid
        match (result) {
            case CredentialStatus.Invalid => ()
            case _ => throw Exception("expected Invalid at index 3, got: " + result.toByte().toString())
        }
    }

    @TestCase
    func testGetStatus_outOfRange_throws(): Unit {
        let gs = GetStatus()
        let testClaims = buildTestClaims()
        var threw = false
        try {
            let _ = gs.getStatus(
                999i64,  // way out of range for 1-byte status list
                "https://example.com/status",
                StatusListTokenFormat.Jwt,
                { _fmt: StatusListTokenFormat, _url: String, _nowSecs: Float64, _clockSkew: Float64 =>
                    testClaims
                },
                1700000100.0,
                60.0
            )
        } catch (e: StatusError) {
            threw = true
            if (!e.message.contains("OutOfRange")) {
                throw Exception("expected 'OutOfRange', got: " + e.message)
            }
        }
        if (!threw) {
            throw Exception("expected StatusError for out-of-range index")
        }
    }

    @TestCase
    func testGetStatus_fourBitList(): Unit {
        // Verify end-to-end with 4-bit entries
        // [0xAB] = 1010_1011: lower nibble=0x0B, upper nibble=0x0A
        // With 4-bit BitsPerStatus: idx0=0x0B (ApplicationSpecific), idx1=0x0A
        let rawStatus: Array<UInt8> = [0xABu8]
        let compressed = compressDeflateHelper(rawStatus)
        let lstB64 = encodeBase64Url(compressed)

        let sl = StatusList(
            bitsPerStatus: BitsPerStatus.Four,
            compressedList: lstB64,
            aggregationUri: None<String>
        )
        let claims = StatusListTokenClaims(
            subject: "https://example.com/status",
            issuedAt: 1700000000.0,
            expirationTime: None<Float64>,
            timeToLive: None<Float64>,
            statusList: sl
        )

        let gs = GetStatus()
        let result0 = gs.getStatus(
            0i64,
            "https://example.com/status",
            StatusListTokenFormat.Jwt,
            { _fmt: StatusListTokenFormat, _url: String, _nowSecs: Float64, _clockSkew: Float64 =>
                claims
            },
            1700000100.0,
            60.0
        )
        // lower nibble of 0xAB = 0x0B = ApplicationSpecific
        match (result0) {
            case CredentialStatus.ApplicationSpecific(v) =>
                @Expect(v, 0x0Bu8)
            case _ => throw Exception("expected ApplicationSpecific(0x0B) at index 0")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 27: runStatiumDemo smoke test
// ---------------------------------------------------------------------------

@Test
class StatiumDemoSmokeUT {

    @TestCase
    func testRunStatiumDemo(): Unit {
        let result = runStatiumDemo()
        if (!result.contains("Statium demo")) {
            throw Exception("runStatiumDemo() missing 'Statium demo', got: " + result)
        }
        if (!result.contains("Valid")) {
            throw Exception("runStatiumDemo() missing 'Valid', got: " + result)
        }
    }
}

// ---------------------------------------------------------------------------
// Test 28: CWT origin-based subject comparison (P1 bug fix verification)
// ---------------------------------------------------------------------------

@Test
class CwtOriginSubjectUT {

    // Same CWT token bytes as CwtDecoderUT (sub = "https://example.com/status")
    let cwtToken: Array<UInt8> = [
        0xD2u8, 0x84u8, 0x58u8, 0x1Eu8, 0xA1u8, 0x10u8, 0x78u8, 0x1Au8, 0x61u8, 0x70u8, 0x70u8, 0x6Cu8,
        0x69u8, 0x63u8, 0x61u8, 0x74u8, 0x69u8, 0x6Fu8, 0x6Eu8, 0x2Fu8, 0x73u8, 0x74u8, 0x61u8, 0x74u8,
        0x75u8, 0x73u8, 0x6Cu8, 0x69u8, 0x73u8, 0x74u8, 0x2Bu8, 0x63u8, 0x77u8, 0x74u8, 0xA0u8, 0x58u8,
        0x36u8, 0xA3u8, 0x02u8, 0x78u8, 0x1Au8, 0x68u8, 0x74u8, 0x74u8, 0x70u8, 0x73u8, 0x3Au8, 0x2Fu8,
        0x2Fu8, 0x65u8, 0x78u8, 0x61u8, 0x6Du8, 0x70u8, 0x6Cu8, 0x65u8, 0x2Eu8, 0x63u8, 0x6Fu8, 0x6Du8,
        0x2Fu8, 0x73u8, 0x74u8, 0x61u8, 0x74u8, 0x75u8, 0x73u8, 0x06u8, 0x1Au8, 0x65u8, 0x53u8, 0xF1u8,
        0x00u8, 0x19u8, 0xFFu8, 0xFDu8, 0xA2u8, 0x64u8, 0x62u8, 0x69u8, 0x74u8, 0x73u8, 0x01u8, 0x63u8,
        0x6Cu8, 0x73u8, 0x74u8, 0x43u8, 0x5Bu8, 0x05u8, 0x00u8, 0x44u8, 0xDEu8, 0xADu8, 0xBEu8, 0xEFu8
    ]

    @TestCase
    func testOriginMatch_fullPathFetchedFrom(): Unit {
        // CWT sub = "https://example.com/status"
        // fetchedFrom = "https://example.com/status/list/42"  (different path, same origin)
        // Origin of both = "https://example.com" => should PASS after P1 fix.
        let claims = decodeCwtStatusListToken(
            cwtToken,
            Some("https://example.com/status/list/42"),
            1700000100.0,
            60.0
        )
        @Expect(claims.subject, "https://example.com/status")
    }

    @TestCase
    func testOriginMatch_exactSubMatch(): Unit {
        // fetchedFrom exactly equals sub: both have same origin => should pass
        let claims = decodeCwtStatusListToken(
            cwtToken,
            Some("https://example.com/status"),
            1700000100.0,
            60.0
        )
        @Expect(claims.subject, "https://example.com/status")
    }

    @TestCase
    func testOriginMismatch_differentHost(): Unit {
        // fetchedFrom has different host => different origin => should FAIL
        var threw = false
        try {
            let _ = decodeCwtStatusListToken(
                cwtToken,
                Some("https://attacker.com/status"),
                1700000100.0,
                60.0
            )
        } catch (e: StatusError) {
            threw = true
            if (!e.message.contains("CwtSubjectMismatch") && !e.message.contains("Mismatch")) {
                throw Exception("expected CwtSubjectMismatch, got: " + e.message)
            }
        }
        if (!threw) {
            throw Exception("expected StatusError for different host")
        }
    }

    @TestCase
    func testOriginMismatch_differentScheme(): Unit {
        // http:// vs https:// origin => different origin => should FAIL
        var threw = false
        try {
            let _ = decodeCwtStatusListToken(
                cwtToken,
                Some("http://example.com/status"),
                1700000100.0,
                60.0
            )
        } catch (e: StatusError) {
            threw = true
        }
        if (!threw) {
            throw Exception("expected StatusError for different scheme")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 29: StatusListTokenFetcher.getStatusClaims (offline, injected mocks)
//
// Strategy: StatusListTokenFetcher does network I/O only via the injected
// NetworkingServiceType, and signature checks only via the injected
// VerifyStatusListTokenSignature. By supplying a fake NetworkingService that
// returns prebuilt token bytes and a fake verifier (no-op / throwing), the
// full getStatusClaims fetch->verify->decode chain runs entirely offline.
//
// Covers public symbols:
//   StatusListTokenFetcher, StatusListTokenFetcherType, getStatusClaims,
//   create, NetworkingServiceType, VerifyStatusListTokenSignature.
// ---------------------------------------------------------------------------

// Fake NetworkingServiceType: returns canned bytes, records the requested url+headers.
class FakeNetworkingService <: NetworkingServiceType {
    let _payload: Array<UInt8>
    var lastUrl: String = ""
    var lastAcceptHeader: String = ""
    var callCount: Int64 = 0

    init(payload: Array<UInt8>) {
        _payload = payload
    }

    public func get(url: String, headers: Array<(String, String)>): Array<UInt8> {
        callCount = callCount + 1
        lastUrl = url
        var i = 0
        while (i < headers.size) {
            if (headers[i][0] == "Accept") {
                lastAcceptHeader = headers[i][1]
            }
            i = i + 1
        }
        return _payload
    }
}

// Fake verifier that succeeds (no-op) and records the call.
class NoopVerifier <: VerifyStatusListTokenSignature {
    var verifyCalled: Bool = false
    var lastFormat: StatusListTokenFormat = StatusListTokenFormat.Jwt
    var lastAtSecs: Float64 = -1.0

    public func verify(tokenBytes: Array<UInt8>, format: StatusListTokenFormat, atSecs: Float64): Unit {
        verifyCalled = true
        lastFormat = format
        lastAtSecs = atSecs
        // accept: do nothing
    }
}

// Fake verifier that always rejects.
class FailingVerifier <: VerifyStatusListTokenSignature {
    public func verify(tokenBytes: Array<UInt8>, format: StatusListTokenFormat, atSecs: Float64): Unit {
        throw StatusError("InvalidSignature:test-forced")
    }
}

@Test
class StatusListTokenFetcherUT {

    // Same compact JWT as JwtParserUT: sub=https://example.com/status,
    // iat=1700000000, status_list={bits:1, lst:"WwUA"} (DEFLATE of [0xAA]).
    let jwtCompact: String =
        "eyJhbGciOiJFUzI1NiIsInR5cCI6InN0YXR1c2xpc3Qrand0In0." +
        "eyJzdWIiOiJodHRwczovL2V4YW1wbGUuY29tL3N0YXR1cyIsImlhdCI6MTcwMDAwMDAwMCwic3RhdHVzX2xpc3QiOnsiYml0cyI6MSwibHN0IjoiV3dVQSJ9fQ." +
        "3q2-7w"

    // Same CWT token bytes as CwtDecoderUT (sub = https://example.com/status).
    let cwtToken: Array<UInt8> = [
        0xD2u8, 0x84u8, 0x58u8, 0x1Eu8, 0xA1u8, 0x10u8, 0x78u8, 0x1Au8, 0x61u8, 0x70u8, 0x70u8, 0x6Cu8,
        0x69u8, 0x63u8, 0x61u8, 0x74u8, 0x69u8, 0x6Fu8, 0x6Eu8, 0x2Fu8, 0x73u8, 0x74u8, 0x61u8, 0x74u8,
        0x75u8, 0x73u8, 0x6Cu8, 0x69u8, 0x73u8, 0x74u8, 0x2Bu8, 0x63u8, 0x77u8, 0x74u8, 0xA0u8, 0x58u8,
        0x36u8, 0xA3u8, 0x02u8, 0x78u8, 0x1Au8, 0x68u8, 0x74u8, 0x74u8, 0x70u8, 0x73u8, 0x3Au8, 0x2Fu8,
        0x2Fu8, 0x65u8, 0x78u8, 0x61u8, 0x6Du8, 0x70u8, 0x6Cu8, 0x65u8, 0x2Eu8, 0x63u8, 0x6Fu8, 0x6Du8,
        0x2Fu8, 0x73u8, 0x74u8, 0x61u8, 0x74u8, 0x75u8, 0x73u8, 0x06u8, 0x1Au8, 0x65u8, 0x53u8, 0xF1u8,
        0x00u8, 0x19u8, 0xFFu8, 0xFDu8, 0xA2u8, 0x64u8, 0x62u8, 0x69u8, 0x74u8, 0x73u8, 0x01u8, 0x63u8,
        0x6Cu8, 0x73u8, 0x74u8, 0x43u8, 0x5Bu8, 0x05u8, 0x00u8, 0x44u8, 0xDEu8, 0xADu8, 0xBEu8, 0xEFu8
    ]

    @TestCase
    func testGetStatusClaims_jwt_happy(): Unit {
        let jwtBytes = jwtCompact.toArray()  // UTF-8 bytes of compact JWT
        let net = FakeNetworkingService(jwtBytes)
        let verifier = NoopVerifier()
        let fetcher = StatusListTokenFetcher(
            networkingService: net,
            verifier: verifier,
            nowSecs: -1.0   // use the nowSecs passed to getStatusClaims
        )

        let claims = fetcher.getStatusClaims(
            "https://example.com/status",
            StatusListTokenFormat.Jwt,
            1700000100.0,
            60.0
        )

        @Expect(claims.subject, "https://example.com/status")
        @Expect(claims.issuedAt, 1700000000.0)
        @Expect(claims.statusList.bitsPerStatus.rawValue(), 1i64)
        @Expect(claims.statusList.compressedList, "WwUA")

        // Verify the collaborators were actually driven.
        @Expect(net.callCount, 1i64)
        @Expect(net.lastUrl, "https://example.com/status")
        @Expect(net.lastAcceptHeader, "application/statuslist+jwt")
        @Expect(verifier.verifyCalled, true)
    }

    @TestCase
    func testGetStatusClaims_typeAsInterface(): Unit {
        // Exercise the StatusListTokenFetcherType interface binding.
        let jwtBytes = jwtCompact.toArray()
        let fetcher: StatusListTokenFetcherType = StatusListTokenFetcher(
            networkingService: FakeNetworkingService(jwtBytes),
            verifier: NoopVerifier(),
            nowSecs: -1.0
        )
        let claims = fetcher.getStatusClaims(
            "https://example.com/status",
            StatusListTokenFormat.Jwt,
            1700000100.0,
            60.0
        )
        @Expect(claims.subject, "https://example.com/status")
    }

    @TestCase
    func testGetStatusClaims_cwt_happy(): Unit {
        let net = FakeNetworkingService(cwtToken)
        let verifier = NoopVerifier()
        let fetcher = StatusListTokenFetcher(
            networkingService: net,
            verifier: verifier,
            nowSecs: -1.0
        )
        let claims = fetcher.getStatusClaims(
            "https://example.com/status",
            StatusListTokenFormat.Cwt,
            1700000100.0,
            60.0
        )
        @Expect(claims.subject, "https://example.com/status")
        @Expect(claims.statusList.bitsPerStatus.rawValue(), 1i64)
        // CWT request must advertise the CWT media type.
        @Expect(net.lastAcceptHeader, "application/statuslist+cwt")
        @Expect(verifier.lastFormat.fieldHeaderValue(), "application/statuslist+cwt")
    }

    @TestCase
    func testGetStatusClaims_injectedNowSecs_overrides(): Unit {
        // Construct with a fixed nowSecs; the value passed to getStatusClaims
        // should be ignored (mirrors iOS injected-clock behaviour).
        let jwtBytes = jwtCompact.toArray()
        let verifier = NoopVerifier()
        let fetcher = StatusListTokenFetcher(
            networkingService: FakeNetworkingService(jwtBytes),
            verifier: verifier,
            nowSecs: 1700000100.0   // injected clock
        )
        // Pass a wildly different nowSecs; injected one (1700000100) must win.
        let claims = fetcher.getStatusClaims(
            "https://example.com/status",
            StatusListTokenFormat.Jwt,
            9999999999.0,
            60.0
        )
        @Expect(claims.subject, "https://example.com/status")
        // verify() received the injected clock value, not 9999999999.
        @Expect(verifier.lastAtSecs, 1700000100.0)
    }

    @TestCase
    func testGetStatusClaims_verifierFailure_propagates(): Unit {
        let jwtBytes = jwtCompact.toArray()
        let fetcher = StatusListTokenFetcher(
            networkingService: FakeNetworkingService(jwtBytes),
            verifier: FailingVerifier(),
            nowSecs: -1.0
        )
        var threw = false
        try {
            let _ = fetcher.getStatusClaims(
                "https://example.com/status",
                StatusListTokenFormat.Jwt,
                1700000100.0,
                60.0
            )
        } catch (e: StatusError) {
            threw = true
            if (!e.message.contains("InvalidSignature")) {
                throw Exception("expected 'InvalidSignature', got: " + e.message)
            }
        }
        if (!threw) {
            throw Exception("expected StatusError when verifier rejects")
        }
    }

    @TestCase
    func testCreate_factory_buildsFetcher(): Unit {
        // StatusListTokenFetcher.create wires a real NetworkingService and the
        // system clock (nowSecs = -1.0). We only assert it constructs and yields
        // a StatusListTokenFetcherType — no network call is performed here.
        let verifier = NoopVerifier()
        let fetcher: StatusListTokenFetcherType = StatusListTokenFetcher.create(verifier)
        // The returned object must be a StatusListTokenFetcher instance.
        match (fetcher) {
            case _: StatusListTokenFetcher => ()
            case _ => throw Exception("create() did not return a StatusListTokenFetcher")
        }
    }
}

// ---------------------------------------------------------------------------
// Test 30: GetStatusType interface binding + NetworkingService construction
//
// Covers public symbols: GetStatusType, NetworkingService, NetworkingServiceType.
// ---------------------------------------------------------------------------

@Test
class GetStatusTypeAndNetworkingUT {

    @TestCase
    func testGetStatusType_interfaceBinding(): Unit {
        // Use GetStatus through the GetStatusType interface (offline, injected claims).
        let gs: GetStatusType = GetStatus()

        let sl = StatusList(
            bitsPerStatus: BitsPerStatus.One,
            compressedList: "WwUA",  // DEFLATE of [0xAA]
            aggregationUri: None<String>
        )
        let testClaims = StatusListTokenClaims(
            subject: "https://example.com/status",
            issuedAt: 1700000000.0,
            expirationTime: None<Float64>,
            timeToLive: None<Float64>,
            statusList: sl
        )

        // index 1 of [0xAA] (1-bit) = 1 => Invalid
        let result = gs.getStatus(
            1i64,
            "https://example.com/status",
            StatusListTokenFormat.Jwt,
            { _fmt: StatusListTokenFormat, _url: String, _nowSecs: Float64, _clockSkew: Float64 =>
                testClaims
            },
            1700000100.0,
            60.0
        )
        match (result) {
            case CredentialStatus.Invalid => ()
            case _ => throw Exception("expected Invalid via GetStatusType, got: " + result.toByte().toString())
        }
    }

    @TestCase
    func testGetStatusType_referenceOverload(): Unit {
        let gs: GetStatusType = GetStatus()
        let sl = StatusList(
            bitsPerStatus: BitsPerStatus.One,
            compressedList: "WwUA",
            aggregationUri: None<String>
        )
        let testClaims = StatusListTokenClaims(
            subject: "https://example.com/status",
            issuedAt: 1700000000.0,
            expirationTime: None<Float64>,
            timeToLive: None<Float64>,
            statusList: sl
        )
        let ref = StatusReference(idx: 0i64, uri: "https://example.com/status")
        // index 0 of [0xAA] (1-bit) = 0 => Valid
        let result = gs.getStatus(
            ref,
            StatusListTokenFormat.Jwt,
            { _fmt: StatusListTokenFormat, _url: String, _nowSecs: Float64, _clockSkew: Float64 =>
                testClaims
            },
            1700000100.0,
            60.0
        )
        match (result) {
            case CredentialStatus.Valid => ()
            case _ => throw Exception("expected Valid via GetStatusType reference overload")
        }
    }

    @TestCase
    func testNetworkingService_constructsAsInterface(): Unit {
        // Construct the real NetworkingService and bind it to its interface.
        // No get() call is made (would require live network); we only assert
        // that construction and interface conformance hold.
        let svc: NetworkingServiceType = NetworkingService()
        match (svc) {
            case _: NetworkingService => ()
            case _ => throw Exception("NetworkingService() did not conform to NetworkingServiceType")
        }
    }
}

// ---------------------------------------------------------------------------
// OpenHarmonyTestRunner (real runner: runTests() -> TestReport, self-certifying)
// ---------------------------------------------------------------------------



