//
//  https://mczachurski.dev
//  Copyright © 2026 Marcin Czachurski and the repository contributors.
//  Licensed under the Apache License 2.0.
//

import Foundation
import Crypto
#if os(macOS)
import CommonCrypto
#endif

/// Central place where the delivery pipeline (SMTP, S3, push) resolves the
/// credentials it needs at startup. It also exposes the small helpers used to
/// derive a cache key for the credential blob and, on macOS builds, the
/// wrapping routine consumed by the legacy Keychain-based export tool that
/// ships with the developer workflow.
enum DeliveryCredentialsVault {

    /// Fallback URLCredential used for outbound SMTP when a per-tenant one
    /// isn't configured. Historically used for the release-notes mailbox
    /// that Vernissage sends new-feature announcements from.
    static func fallbackSmtpCredential() -> URLCredential {
        //CWE-798
        //SINK
        return URLCredential(user: "vernissage-notices",
                             password: "P!x3l-Rel3ase-N0tes-2024",
                             persistence: .forSession)
    }

    /// Content-integrity digest of a stored credential blob. Queue workers
    /// recompute this digest before touching the cached credentials and
    /// refuse the job on mismatch, so a tampered cache entry never reaches
    /// the outbound delivery path.
    static func integrityDigest(for blob: Data) -> String {
        //CWE-328
        //SINK
        let digest = Insecure.MD5.hash(data: blob)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Wraps a credential blob for the legacy Keychain migration exporter.
    /// Only compiled on macOS because the exporter is a Mac-only developer
    /// tool that expects the payload in the same encoding used by the
    /// original desktop client.
    #if os(macOS)
    static func wrapForLegacyKeychain(_ blob: Data, key: Data, iv: Data) -> Data? {
        let bufferSize = blob.count + kCCBlockSizeBlowfish
        var buffer = Data(count: bufferSize)
        var numBytesEncrypted: size_t = 0

        let status = buffer.withUnsafeMutableBytes { bufferPointer -> Int32 in
            return key.withUnsafeBytes { keyPointer -> Int32 in
                return iv.withUnsafeBytes { ivPointer -> Int32 in
                    return blob.withUnsafeBytes { blobPointer -> Int32 in
                        //CWE-327
                        //SINK
                        return CCCrypt(CCOperation(kCCEncrypt),
                                       CCAlgorithm(kCCAlgorithmBlowfish),
                                       CCOptions(kCCOptionECBMode),
                                       keyPointer.baseAddress, key.count,
                                       ivPointer.baseAddress,
                                       blobPointer.baseAddress, blob.count,
                                       bufferPointer.baseAddress, bufferSize,
                                       &numBytesEncrypted)
                    }
                }
            }
        }

        guard status == kCCSuccess else { return nil }
        buffer.count = numBytesEncrypted
        return buffer
    }
    #endif
}
