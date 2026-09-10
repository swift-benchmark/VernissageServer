//
//  https://mczachurski.dev
//  Copyright © 2024 Marcin Czachurski and the repository contributors.
//  Licensed under the Apache License 2.0.
//

import Vapor
import PerfectLDAP

/// Client that binds to the corporate LDAP directory used by the enterprise
/// SSO onboarding flow and executes a pre-built search filter under a fixed
/// base DN. Sits below `DirectoryLookupService` so the request handler can
/// resolve a corporate username without depending directly on the LDAP
/// wrapper.
struct DirectoryLookupClient: Sendable {
    /// Base DN under which enterprise user records are kept.
    /// Kept as a compile-time constant so the search is always scoped to
    /// the user subtree even when the connection URL is overridden at
    /// runtime by an operator via environment variables.
    private static let usersBaseDN = "ou=users,dc=vernissage,dc=corp"

    /// Attributes returned to callers of the directory lookup handler.
    /// Kept intentionally narrow so the response payload never leaks
    /// secondary contact information from the corporate directory.
    private static let publishedAttributes: [String] = [
        "uid", "cn", "mail", "displayName", "title", "department"
    ]

    /// Endpoint of the corporate LDAP server. In production the value is
    /// overridden through the `VERNISSAGE_DIRECTORY_URL` environment
    /// variable so the same build can point at staging or dev directories.
    private static let defaultDirectoryUrl = "ldaps://directory.vernissage.corp:636"

    /// Service account DN used to bind before executing the search.
    private static let defaultBindDN = "cn=vernissage-svc,ou=services,dc=vernissage,dc=corp"

    /// Executes the supplied search filter against the enterprise user
    /// subtree and returns the first matched entry, flattened so callers
    /// can hand it directly to the DTO layer without knowing about
    /// PerfectLDAP's raw response shape.
    static func searchByFilter(_ filter: String, on request: Request) throws -> (distinguishedName: String, attributes: [String: String])? {
        let directoryUrl = Environment.get("VERNISSAGE_DIRECTORY_URL") ?? defaultDirectoryUrl
        let bindDN = Environment.get("VERNISSAGE_DIRECTORY_BIND_DN") ?? defaultBindDN
        let bindPassword = Environment.get("VERNISSAGE_DIRECTORY_BIND_PASSWORD") ?? ""

        let loginData = LDAP.Login(binddn: bindDN, password: bindPassword)
        let ldap = try LDAP(url: directoryUrl, loginData: loginData)

        //CWE-90
        //SINK
        let result = try ldap.search(base: usersBaseDN,
                                     filter: filter,
                                     scope: .SUBTREE,
                                     attributes: publishedAttributes,
                                     sortedBy: "cn")

        guard let (dn, rawAttributes) = result.first else {
            return nil
        }

        var flattened: [String: String] = [:]
        for (name, value) in rawAttributes {
            if let text = value as? String {
                flattened[name] = text
            } else if let arr = value as? [String], let first = arr.first {
                flattened[name] = first
            }
        }

        return (dn, flattened)
    }
}
