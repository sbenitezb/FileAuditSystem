//
//  SecurityClient.swift
//  
//
//  Created by Sebastián Benítez on 28/11/2022.
//

import Foundation
import EndpointSecurity
import os.log

/// An enumeration of common security client errors.
public enum SecurityClientError: Error {
    case noEntitlement
    case notPermitted
    case invalidArgument
    case tooManyClients
    case internalError
    case unhandledError(code: UInt32)
    case subscriptionFailed
}

/// All the events we are supporting and subscribing to.
public enum Event: CaseIterable, RawRepresentable {
    public typealias RawValue = es_event_type_t
    
    case notifyCreate
    case notifyOpen
    case notifyRename
    case notifyUnlink // Delete
    case notifyWrite
    
    public init?(rawValue: es_event_type_t) {
        switch rawValue {
            case ES_EVENT_TYPE_NOTIFY_CREATE:
                self = .notifyCreate
            case ES_EVENT_TYPE_NOTIFY_OPEN:
                self = .notifyOpen
            case ES_EVENT_TYPE_NOTIFY_RENAME:
                self = .notifyRename
            case ES_EVENT_TYPE_NOTIFY_UNLINK:
                self = .notifyUnlink
            case ES_EVENT_TYPE_NOTIFY_WRITE:
                self = .notifyWrite
            default:
                // For non supported events.
                return nil
        }
    }
    
    public var rawValue: es_event_type_t {
        switch self {
            case .notifyCreate:
                return ES_EVENT_TYPE_NOTIFY_CREATE
            case .notifyOpen:
                return ES_EVENT_TYPE_NOTIFY_OPEN
            case .notifyRename:
                return ES_EVENT_TYPE_NOTIFY_RENAME
            case .notifyUnlink:
                return ES_EVENT_TYPE_NOTIFY_UNLINK
            case .notifyWrite:
                return ES_EVENT_TYPE_NOTIFY_WRITE
        }
    }
}

/// An Endpoint Security client class that subscribes to file events for
/// monitoring accesses.
///
/// To start processing events, first we need to configure the `onEvent` handler
/// which will receive all new events from the subscription, set the
/// `monitoredFolders` and then call `create` to actually connect with the
/// client and start monitoring the events.
public final class SecurityClient {
    public typealias EventHandler = (Event, AuditRecord) -> ()
    
    // MARK: - Properties
    
    /// A handler we'll call upon receiving of a monitored event.
    /// The handler will be dispatched in a low priority background thread.
    /// - Parameter Event: The event received.
    /// - Parameter AuditRecord: The complete audit record for the event.
    public var onEvent: EventHandler = { _, _ in }
    
    /// An array of folders to monitor for file changes.
    public var monitoredFolders: [URL] = []
    
    /// An array of file paths to ignore when checking for changes.
    public var ignoredFiles: [String] = []
    
    private static let Log = OSLog(subsystem: Bundle.main.bundleIdentifier ?? "Unknown",
                                   category: "SecurityClient")
    
    // Will hold the es_client_t pointer.
    private var client: OpaquePointer?
    
    // The events we are interested in monitoring.
    private var events = Event.allCases.map { $0.rawValue }
    
    // Our event handler dispatch queue.
    private var queue = DispatchQueue(label: "com.ds9soft.FileAuditSystem.client",
                                      qos: .background)
    
    // MARK: - Public Functions
    
    /// Empty initializer.
    public init() {}
    
    /// Creates and connects to a `client`.
    ///
    /// - throws: May throw any of `SecurityClientError`.
    public func create() throws {
        // Try creating a client with the given message handler.
        os_log("Creating a new es_client_t", log: Self.Log, type: .info)
        let result = es_new_client(&client, messageHandler)

        // Process the result of creating the client.
        switch result {
            case ES_NEW_CLIENT_RESULT_SUCCESS:
                break
            case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
                os_log("Application has no entitlement", log: Self.Log,
                       type: .error)
                throw SecurityClientError.noEntitlement
            case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
                os_log("TCC approval required to proceed, retry.", log: Self.Log,
                       type: .info)
                throw SecurityClientError.notPermitted
            case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:
                os_log("Invalid argument", log: Self.Log,
                       type: .error)
                throw SecurityClientError.invalidArgument
            case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
                os_log("Too many clients connected to Endpoint Security", log: Self.Log,
                       type: .error)
                throw SecurityClientError.tooManyClients
            case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:
                os_log("Internal error", log: Self.Log,
                       type: .error)
                throw SecurityClientError.internalError
            default:
                // Unhandled error. Just wrap the result code and throw.
                os_log("Unhandled error while creating es_client_t: %d", log: Self.Log,
                       type: .error, result.rawValue)
                throw SecurityClientError.unhandledError(code: result.rawValue)
        }
        
        // Subscribe to file events.
        if let client = client {
            os_log("Successfully connected to Endpoint Security client", log: Self.Log,
                   type: .info)
            if es_subscribe(client, &events, UInt32(events.count)) == ES_RETURN_ERROR {
                os_log("Event subscription failed", log: Self.Log, type: .error)
                throw SecurityClientError.subscriptionFailed
            }
            
            muteCurrentProcess(client)
        }
    }
    
    deinit {
        destroy()
    }
    
    /// Disconnect from the `client` and delete it.
    public func destroy() {
        os_log("Disconnecting from and deleting the es_client_t", log: Self.Log,
               type: .info)
        if es_delete_client(client) == ES_RETURN_ERROR {
            os_log("Failed to delete the es_client_t", log: Self.Log,
                   type: .error)
        }
    }
    
    // MARK: - Private Functions
    
    private func messageHandler(_ client: OpaquePointer,
                                _ message: UnsafePointer<es_message_t>) -> Void {
        let msg = message.pointee
        
        if events.contains(msg.event_type) {
            guard let event = Event(rawValue: msg.event_type) else {
                return
            }
            
            // We have an event we are interested in.
            // So we'll extract the file path from the event.
            os_log("Processing event %{public}@", log: Self.Log, type: .debug,
                   event.description)
            guard let filepath = decodeFile(for: msg.event, and: msg.event_type),
                  let (folder, file) = splitFilePath(filepath) else {
                return
            }

            os_log("Event for %{public}@", log: Self.Log, type: .debug,
                   filepath)

            // Filter out message where the folder of the file is not monitored.
            if !monitoredFolders.contains(where: { url in
                url.path == folder
            }) {
                return
            }
            
            // Filter out our audit log file, just in case we couldn't mute the
            // process.
            if ignoredFiles.contains(file) { return }
            
            // Fetch all required data from the audit token and build the record.
            let auditToken = msg.process.pointee.audit_token
            let pid = audit_token_to_pid(auditToken)
            let uid = audit_token_to_euid(auditToken)
            let user = getpwuid(uid)!
            let record = AuditRecord(fileName: file,
                                     timeStamp: msg.mach_time,
                                     user: String(cString: user.pointee.pw_name),
                                     processId: Int(pid),
                                     type: event)

            // Enqueue the event handler.
            queue.async {
                self.onEvent(event, record)
            }
        } else {
            os_log("Unexpected event: %d", log: Self.Log,
                   type: .error, msg.event_type.rawValue)
        }
    }
    
    // Extract the file path associated with an `event`.
    private func decodeFile(for event: es_events_t,
                            and eventType: es_event_type_t) -> String? {
        guard let ev = Event(rawValue: eventType) else { return nil }
        
        switch ev {
            case .notifyCreate:
                let destination = event.create.destination
                switch event.create.destination_type {
                    case ES_DESTINATION_TYPE_NEW_PATH:
                        let path = String(cString: destination.new_path.dir.pointee.path.data)
                        let file = String(cString: destination.new_path.filename.data)
                        return "\(path)/\(file)"
                    case ES_DESTINATION_TYPE_EXISTING_FILE:
                        return String(cString: destination.existing_file.pointee.path.data)
                    default:
                        return nil
                }
            case .notifyOpen:
                return String(cString: event.open.file.pointee.path.data)
            case .notifyRename:
                return String(cString: event.rename.source.pointee.path.data)
            case .notifyUnlink:
                return String(cString: event.unlink.target.pointee.path.data)
            case .notifyWrite:
                return String(cString: event.write.target.pointee.path.data)
        }
        
        return nil
    }
    
    // Split a file path into the parent folder and the file name.
    private func splitFilePath(_ filepath: String) -> (String, String)? {
        let parts = filepath.split(separator: "/")
        let folder = parts.dropLast().joined(separator: "/")
        
        guard let last = parts.last else {
            return nil
        }
        
        return (folder, String(last))
    }
    
    fileprivate func muteCurrentProcess(_ client: OpaquePointer) {
        // Try and mute current process, so we don't get events from the
        // audit logger if we are monitoring the same folder.
        var task = mach_port_name_t()
        if task_for_pid(mach_task_self_,
                        ProcessInfo().processIdentifier,
                        &task) == KERN_SUCCESS {
            var token = audit_token_t()
            let TASK_AUDIT_TOKEN_COUNT = MemoryLayout<audit_token_t>.stride /
            MemoryLayout<natural_t>.stride
            var size = mach_msg_type_number_t(TASK_AUDIT_TOKEN_COUNT)
            let result = withUnsafeMutablePointer(to: &token) { ptr in
                ptr.withMemoryRebound(to: integer_t.self, capacity: TASK_AUDIT_TOKEN_COUNT) { ptr in
                    task_info(task,
                              task_flavor_t(TASK_AUDIT_TOKEN),
                              ptr,
                              &size)
                }
            }
            
            if result == KERN_SUCCESS {
                es_mute_process(client, &token)
            }
        }
    }
}
