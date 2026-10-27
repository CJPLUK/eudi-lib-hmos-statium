/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * networking_service.cj
 *
 * Ported from iOS Sources/Services/NetworkingService.swift.
 *
 * iOS actor NetworkingService -> Cangjie class (actor keyword absent in Cangjie;
 * thread-safety delegated to stdx.net.http Client which is thread-safe).
 *
 * Platform mapping:
 *   iOS URLSession.data(for:) async -> stdx.net.http Client.send() (synchronous)
 *   iOS Data -> Array<UInt8>
 */
package ohos_app_cangjie_eudi_cjstatium.statium.network

import stdx.net.http.*
import stdx.net.tls.TlsClientConfig
import std.io.InputStream
import std.time.*
import ohos_app_cangjie_eudi_cjstatium.statium.model.StatusError

/**
 * Interface for HTTP GET requests.
 * Mirrors iOS protocol NetworkingServiceType.
 */
public interface NetworkingServiceType {
    /**
     * Perform an HTTP GET request with the given headers.
     * Returns the response body bytes on success (HTTP 200).
     * Throws StatusError on transport error or non-200 response.
     */
    func get(url: String, headers: Array<(String, String)>): Array<UInt8>
}

/**
 * Default implementation backed by stdx.net.http Client.
 * Mirrors iOS actor NetworkingService.
 */
public class NetworkingService <: NetworkingServiceType {

    private let _client: Client

    public init() {
        // HTTPS requires an explicit TLS config or stdx throws
        // "TLS must be configured". Default verifies the system cert store.
        // Bounded timeouts so a black-holed connection fails fast and the
        // transport-retry loop in get() can re-send.
        _client = ClientBuilder()
            .tlsConfig(TlsClientConfig())
            .readTimeout(Duration.second * 45)
            .writeTimeout(Duration.second * 30)
            .build()
    }

    /**
     * Execute an HTTP GET with the given headers.
     * Throws StatusError on any failure.
     */
    public func get(url: String, headers: Array<(String, String)>): Array<UInt8> {
        // Transport-level retry: the pooled keep-alive connection may have been
        // closed server-side while the app idled; the first write then fails
        // with SocketException ECONNABORTED. Re-send on a fresh attempt (iOS
        // URLSession does this transparently). Non-200 statuses are not
        // transport failures and are never retried.
        var statusCode: Int64 = 0
        var body = Array<UInt8>(0, repeat: 0u8)
        var attempt = 0
        while (true) {
            try {
                var reqBuilder = HttpRequestBuilder()
                    .url(url)
                    .method("GET")

                var i: Int64 = 0
                while (i < headers.size) {
                    reqBuilder = reqBuilder.header(headers[i][0], headers[i][1])
                    i = i + 1
                }

                let resp = _client.send(reqBuilder.build())
                statusCode = Int64(resp.status)
                body = readAllBytes(resp.body)
                break
            } catch (e: Exception) {
                attempt++
                if (attempt >= 3) {
                    throw StatusError("NetworkError:" + e.message)
                }
                sleep(Duration.millisecond * 300)
            }
        }

        if (statusCode != 200) {
            throw StatusError("BadServerResponse:status=" + statusCode.toString())
        }

        return body
    }
}

/**
 * Read all bytes from an InputStream into Array<UInt8>.
 */
func readAllBytes(stream: InputStream): Array<UInt8> {
    let buf = Array<UInt8>(4096, repeat: 0u8)
    var result = Array<UInt8>(0, repeat: 0u8)
    var n = stream.read(buf)
    while (n > 0) {
        let newResult = Array<UInt8>(result.size + n, repeat: 0u8)
        result.copyTo(newResult, 0, 0, result.size)
        buf.copyTo(newResult, 0, result.size, n)
        result = newResult
        n = stream.read(buf)
    }
    return result
}
