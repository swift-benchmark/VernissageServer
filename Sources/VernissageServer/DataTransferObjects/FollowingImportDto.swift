//
//  https://mczachurski.dev
//  Copyright © 2025 Marcin Czachurski and the repository contributors.
//  Licensed under the Apache License 2.0.
//

import Vapor

struct FollowingImportDto {
    var id: String?
    var status: FollowingImportStatusDto
    var startedAt: Date?
    var endedAt: Date?
    var createdAt: Date?
    var updatedAt: Date?
    var followingImportItems: [FollowingImportItemDto]
    var confirmationToken: String?
}

extension FollowingImportDto {
    init(from followingImport: FollowingImport, confirmationToken: String? = nil) {
        self.init(id: followingImport.stringId(),
                  status: FollowingImportStatusDto.from(followingImport.status),
                  startedAt: followingImport.startedAt,
                  endedAt: followingImport.endedAt,
                  createdAt: followingImport.createdAt,
                  updatedAt: followingImport.updatedAt,
                  followingImportItems: followingImport.followingImportItems.map { FollowingImportItemDto(from: $0) },
                  confirmationToken: confirmationToken)
    }
}

extension FollowingImportDto: Content { }
