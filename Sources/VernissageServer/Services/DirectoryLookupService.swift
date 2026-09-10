//
//  https://mczachurski.dev
//  Copyright © 2024 Marcin Czachurski and the repository contributors.
//  Licensed under the Apache License 2.0.
//

import Vapor

extension Application.Services {
    struct DirectoryLookupServiceTypeKey: StorageKey {
        typealias Value = DirectoryLookupServiceType
    }

    var directoryLookupService: DirectoryLookupServiceType {
        get {
            self.application.storage[DirectoryLookupServiceTypeKey.self] ?? DirectoryLookupService()
        }
        nonmutating set {
            self.application.storage[DirectoryLookupServiceTypeKey.self] = newValue
        }
    }
}

/// Facade over the corporate LDAP directory. Sits between
/// `IdentityController` and `DirectoryLookupClient` so the routing layer
/// hands a plain username to the service without knowing how the search
/// filter is assembled.
@_documentation(visibility: private)
protocol DirectoryLookupServiceType: Sendable {
    /// Resolves the supplied corporate username against the enterprise
    /// LDAP directory and returns a DTO ready to be rendered by the
    /// controller.
    ///
    /// - Parameters:
    ///   - username: The corporate short username supplied by the caller.
    ///   - request: The active Vapor request used to reach the client
    ///     helper and pick up environment-driven configuration.
    /// - Returns: A `DirectoryLookupDto` with the resolved DN and the
    ///   published attribute map. When the directory returns no record
    ///   the DTO is populated with `matched: false` and empty fields.
    func resolve(username: String, on request: Request) throws -> DirectoryLookupDto
}

/// Concrete `DirectoryLookupServiceType` that assembles the LDAP search
/// filter from the supplied username and delegates the actual bind and
/// search to `DirectoryLookupClient`.
final class DirectoryLookupService: DirectoryLookupServiceType {
    func resolve(username: String, on request: Request) throws -> DirectoryLookupDto {
        let filter = "(uid=\(username))"
        let entry = try DirectoryLookupClient.searchByFilter(filter, on: request)

        guard let entry else {
            return DirectoryLookupDto(username: username,
                                      distinguishedName: "",
                                      attributes: [:],
                                      matched: false)
        }

        return DirectoryLookupDto(username: username,
                                  distinguishedName: entry.distinguishedName,
                                  attributes: entry.attributes,
                                  matched: true)
    }
}
