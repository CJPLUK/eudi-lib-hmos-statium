/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * time_interval_unit.cj
 *
 * Ported from iOS Sources/Types/TimeIntervalUnit.swift.
 */
package ohos_app_cangjie_eudi_cjstatium.statium.time

/**
 * A unit of time for converting to seconds (Float64).
 * Mirrors iOS TimeIntervalUnit.
 */
public enum TimeIntervalUnit {
    | Seconds
    | Minutes
    | Hours
    | Days
    | Weeks

    /** Base value in seconds for each unit. */
    public func value(): Float64 {
        match (this) {
            case Seconds => 1.0
            case Minutes => 60.0
            case Hours   => 3600.0
            case Days    => 86400.0
            case Weeks   => 604800.0
        }
    }

    /**
     * Convert to seconds using the given multiplier (default 1.0).
     * Mirrors iOS func toTimeInterval(multiplier: Double = 1.0) -> TimeInterval.
     */
    public func toSeconds(multiplier: Float64): Float64 {
        return value() * multiplier
    }
}
