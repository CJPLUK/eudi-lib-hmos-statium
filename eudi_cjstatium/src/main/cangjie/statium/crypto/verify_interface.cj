/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * verify_interface.cj
 *
 * Ported from iOS Sources/Types/VerifyStatusListTokenSignature.swift.
 */
package ohos_app_cangjie_eudi_cjstatium.statium.crypto

import ohos_app_cangjie_eudi_cjstatium.statium.model.StatusListTokenFormat

/**
 * Protocol for verifying the signature of a status list token.
 *
 * Mirrors iOS protocol VerifyStatusListTokenSignature: Sendable.
 * Callers implement this interface with the appropriate crypto backend.
 *
 * The `at` parameter is the validation time as seconds since epoch (Float64),
 * matching iOS's Date.timeIntervalSince1970.
 */
public interface VerifyStatusListTokenSignature {
    /**
     * Verify the signature of the given status list token bytes.
     *
     * - tokenBytes: raw bytes of the token (JWT UTF-8 or CWT binary)
     * - format:     Jwt or Cwt
     * - atSecs:     validation time as seconds since epoch
     *
     * Throws StatusError on invalid signature or structural error.
     */
    func verify(tokenBytes: Array<UInt8>, format: StatusListTokenFormat, atSecs: Float64): Unit
}
