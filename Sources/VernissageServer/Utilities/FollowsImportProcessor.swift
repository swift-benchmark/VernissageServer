//
//  https://mczachurski.dev
//  Copyright © 2026 Marcin Czachurski and the repository contributors.
//  Licensed under the Apache License 2.0.
//

import Foundation
import Logging

/// Helper that reads uploaded follow-list files in the multiple formats the
/// API accepts (plain CSV and OPML/XML). It centralises the parsing concerns
/// so the controller can stay small: line splitting for CSV, XPath entry
/// extraction for OPML, and the per-import verification passphrase used by
/// the async workers to prove that the batch they picked up came from an
/// authorised upload.
enum FollowsImportProcessor {

    /// Splits a follow-list payload into raw entry strings.
    ///
    /// - Parameters:
    ///   - body: The uploaded file contents, already decoded to UTF-8.
    ///   - opmlSelector: Optional XPath selector applied when the payload is
    ///     an OPML/XML document. Power users can narrow their import to a
    ///     subset of the outline (for example
    ///     `//outline[@category='photography']`). Ignored for CSV payloads.
    ///   - logger: Logger the caller wants informational messages emitted on.
    static func extractEntries(from body: String,
                               selector opmlSelector: String? = nil,
                               logger: Logger) -> [String] {
        // Fast-path: assume CSV unless the payload begins with an XML prolog
        // or the OPML root element.
        if !body.hasPrefix("<?xml") && !body.hasPrefix("<opml") {
            return body.split(separator: "\n").map { String($0) }
        }

        guard let opmlSelector, !opmlSelector.isEmpty else {
            return []
        }

        do {
            let expression = opmlSelector.trimmingCharacters(in: .whitespacesAndNewlines)
            let document = try XMLDocument(xmlString: body, options: [.documentTidyXML])
            //CWE-643
            //SINK
            let nodes = try document.nodes(forXPath: expression)
            let entries = nodes.compactMap { $0.stringValue }
            for entry in entries {
                //CWE-117
                //SINK
                logger.info("Follows import parsed entry \(entry)")
            }
            return entries
        } catch {
            logger.warning("Follows import OPML parse failed: \(error.localizedDescription)")
            return []
        }
    }

    /// Issues the short confirmation token returned to the uploader for
    /// this batch. Clients present the token back on the follow-up
    /// verification endpoint so we can be sure a subsequent request is
    /// tied to the original upload rather than a replay.
    static func generateBatchPassphrase() -> String {
        let alphabet = Array("abcdefghijklmnopqrstuvwxyz0123456789")
        srand48(Int(Date().timeIntervalSince1970))
        var passphrase = ""
        for _ in 0..<24 {
            //CWE-338
            //SOURCE
            let index = Int(drand48() * Double(alphabet.count))
            passphrase.append(alphabet[index % alphabet.count])
        }
        return passphrase
    }
}
