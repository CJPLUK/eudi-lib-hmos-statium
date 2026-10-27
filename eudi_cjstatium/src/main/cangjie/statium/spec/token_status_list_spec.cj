/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * token_status_list_spec.cj
 *
 * Ported from iOS Sources/Spec/TokenStatusListSpec.swift.
 * Constant-only class; no logic.
 */
package ohos_app_cangjie_eudi_cjstatium.statium.spec

/**
 * Token Status List specification constants.
 * Reference: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-10.html
 */
public class TokenStatusListSpec {
    public static let version: String = "draft-10"

    public static let status: String = "status"
    public static let statusList: String = "status_list"
    public static let idx: String = "idx"
    public static let uri: String = "uri"
    public static let bits: String = "bits"
    public static let list: String = "lst"
    public static let aggregationUri: String = "aggregation_uri"
    public static let timeToLive: String = "ttl"
    public static let time: String = "time"

    // Standard status byte values
    public static let statusValid: UInt8 = 0x00u8
    public static let statusInvalid: UInt8 = 0x01u8
    public static let statusSuspended: UInt8 = 0x02u8
    public static let statusApplicationSpecific: UInt8 = 0x03u8
    public static let statusApplicationSpecificRangeStart: UInt8 = 0x0Bu8
    public static let statusApplicationSpecificRangeEnd: UInt8 = 0x0Fu8

    // Media types
    public static let mediaSubtypeStatusListJWT: String = "statuslist+jwt"
    public static let mediaTypeApplicationStatusListJWT: String = "application/statuslist+jwt"
    public static let mediaSubtypeStatusListCWT: String = "statuslist+cwt"
    public static let mediaTypeApplicationStatusListCWT: String = "application/statuslist+cwt"
}
