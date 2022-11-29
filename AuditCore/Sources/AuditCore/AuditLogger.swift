//
//  AuditLogger.swift
//  
//
//  Created by Sebastián Benítez on 29/11/2022.
//

import Foundation
import os.log

/// Implements a simple audit log.
public final class AuditLogger {
    // MARK: - Properties
    
    private var fileHandle: FileHandle
    
    private static let Log = OSLog(subsystem: Bundle.main.bundleIdentifier ?? "Unknown",
                                   category: "AuditLogger")
    
    // MARK: - Public Functions
    
    /// Initializes the `AuditLogger` with the URL of the audit file.
    ///
    /// - Parameter fileURL: The URL of the audit file.
    public init(fileURL: URL) throws {
        self.fileHandle = try FileHandle(forWritingTo: fileURL)
    }
    
    deinit {
        _ = try? fileHandle.close()
    }
    
    /// Appends an audit record to the log.
    ///
    /// - Parameter record: An audit record.
    /// - Throws: If fails to seek to end of file or write to it.
    public func append(record: AuditRecord) throws {
        guard let data = record.data else {
            os_log("Failed to encode audit record as utf-8 encoded data: %{public}@",
                   log: Self.Log, type: .error, record.csv)
            return
        }
        
        if #available(macOS 10.15.4, *) {
            try fileHandle.seekToEnd()
            try fileHandle.write(contentsOf: data)
        } else {
            // Fallback on earlier versions
            fileHandle.seekToEndOfFile()
            fileHandle.write(data)
        }
    }
}
