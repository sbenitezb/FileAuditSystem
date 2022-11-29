//
//  AppDelegate.swift
//  FileAuditSystem
//
//  Created by Sebastián Benítez on 28/11/2022.
//

import Cocoa
import AuditCore
import os.log

@main
class AppDelegate: NSObject, NSApplicationDelegate {
    var client = SecurityClient()

    private static let Log = OSLog(subsystem: Bundle.main.bundleIdentifier ?? "Unknown",
                                   category: "AppDelegate")
    private let auditFileName = "FileAuditSystem.txt"
    private var auditFileURL: URL!
    private var auditLogger: AuditLogger?
        
    func applicationDidFinishLaunching(_ aNotification: Notification) {
        // Our audit file will be saved to the Documents folder for simplicity.
        auditFileURL = FileManager.default.urls(for: .documentDirectory,
                                                   in: .userDomainMask).first?
            .appendingPathComponent(auditFileName)
 
        // Create audit file if it does not exist.
        if !FileManager.default.fileExists(atPath: auditFileURL.path) {
            FileManager.default.createFile(atPath: auditFileURL.path,
                                           contents: nil,
                                           attributes: nil)
        }
        
        do {
            // Open the audit log.
            auditLogger = try AuditLogger(fileURL: auditFileURL)
        } catch {
            let alert = NSAlert(error: error)
            alert.messageText = "Failed to initialize AuditLogger"
            alert.runModal()
            NSApp.terminate(self)
        }

        // Our event handler will write the audit record to the audit log.
        if let auditLogger = auditLogger {
            client.onEvent = { event, auditRecord in
                do {
                    try auditLogger.append(record: auditRecord)
                } catch {
                    os_log("Failed to write audit record: %{public}@",
                           log: Self.Log, type: .error, error.localizedDescription)
                }
            }
        }
        
        // We'll add our audit file to the ignored files so we don't log
        // accesses to it if it's in the list of monitored folders.
        client.ignoredFiles = [auditFileURL.lastPathComponent]
        
        // Connect to the client.
        do {
            try client.create()
        } catch SecurityClientError.noEntitlement {
            showErrorAndTerminate(error: SecurityClientError.noEntitlement, msg: "No entitlement")
        } catch SecurityClientError.notPermitted {
            showErrorAndTerminate(error: SecurityClientError.notPermitted, msg: "Not permitted")
        } catch {
            showErrorAndTerminate(error: error, msg: "Failed to create client")
        }
    }

    func applicationWillTerminate(_ aNotification: Notification) {
        // Insert code here to tear down your application
    }

    func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
        return true
    }
    
    // MARK: - Private Functions
    
    private func showErrorAndTerminate(error: Error, msg: String) {
        let alert = NSAlert(error: error)
        alert.messageText = msg
        alert.runModal()
        NSApp.terminate(self)
    }
}

