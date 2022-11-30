//
//  AuditRecord.swift
//  
//
//  Created by Sebastián Benítez on 29/11/2022.
//

import Foundation

/// An entry in the audit log.
public struct AuditRecord {
    // MARK: - Properties
    
    let fileName: String
    let timeStamp: UInt64
    let user: String
    let processId: Int
    let type: Event
    
    public var data: Data? {
        return csv.data(using: .utf8)
    }
    
    public var csv: String {
        return "\(fileName),\(timeStamp.description),\(user),\(processId.description),\(type.description)\n"
    }

    // MARK: - Public Functions
    
    public init(fileName: String, timeStamp: UInt64, user: String, processId: Int, type: Event) {
        self.fileName = fileName
        self.timeStamp = timeStamp
        self.user = user
        self.processId = processId
        self.type = type
    }
}

// An extension to convert an Event to a string representation.
extension Event: CustomStringConvertible {
    public var description: String {
        switch self {
            case .notifyCreate:
                return "Create"
            case .notifyOpen:
                return "Open"
            case .notifyRename:
                return "Rename"
            case .notifyUnlink:
                return "Unlink"
            case .notifyWrite:
                return "Write"
        }
    }
}
