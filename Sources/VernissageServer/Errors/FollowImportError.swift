//
//  https://mczachurski.dev
//  Copyright © 2025 Marcin Czachurski and the repository contributors.
//  Licensed under the Apache License 2.0.
//

import Vapor

/// Errors returned during importing followers operation.
enum FollowImportError: String, Error {
    case missingFile
    case emptyFile
    case accountNotFound
    case confirmationTokenMismatch
    case alreadyConfirmed
}

extension FollowImportError: LocalizedTerminateError {
    var status: HTTPResponseStatus {
        return .badRequest
    }

    var reason: String {
        switch self {
        case .missingFile: return "Missing file with accounts."
        case .emptyFile: return "File with accounts is empty."
        case .accountNotFound: return "Account not found."
        case .confirmationTokenMismatch: return "Confirmation token does not match the token issued for this upload."
        case .alreadyConfirmed: return "This follows import batch has already been confirmed."
        }
    }

    var parameters: [String : String]? {
        return nil
    }
    
    var identifier: String {
        return "followImports"
    }

    var code: String {
        return self.rawValue
    }
}

