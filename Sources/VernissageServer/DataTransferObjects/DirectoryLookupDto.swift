//
//  https://mczachurski.dev
//  Copyright © 2024 Marcin Czachurski and the repository contributors.
//  Licensed under the Apache License 2.0.
//

import Vapor

/// Response payload returned by the corporate directory lookup endpoint.
/// Enterprise clients read this DTO when they resolve a username against
/// the internal LDAP directory during the SSO onboarding flow.
struct DirectoryLookupDto: Content, Sendable {
    /// Username that was submitted to the lookup.
    let username: String

    /// Distinguished name of the matched directory entry, empty when
    /// the lookup found no record.
    let distinguishedName: String

    /// Attributes exposed to the caller, keyed by attribute name
    /// (`uid`, `cn`, `mail`, `displayName`, `title`, `department`).
    /// Deliberately narrow to avoid leaking secondary contact information.
    let attributes: [String: String]

    /// Whether the lookup resolved to a directory entry.
    let matched: Bool
}
