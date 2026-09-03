//
//  https://mczachurski.dev
//  Copyright © 2026 Marcin Czachurski and the repository contributors.
//  Licensed under the Apache License 2.0.
//

import Vapor
import Fluent

extension FollowingImport {
    struct AddConfirmationToken: AsyncMigration {
        func prepare(on database: Database) async throws {
            try await database
                .schema(FollowingImport.schema)
                .field("confirmationToken", .string)
                .field("confirmedAt", .datetime)
                .update()
        }

        func revert(on database: Database) async throws {
            try await database
                .schema(FollowingImport.schema)
                .deleteField("confirmationToken")
                .deleteField("confirmedAt")
                .update()
        }
    }
}
