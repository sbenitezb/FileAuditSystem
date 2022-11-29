//
//  ViewController.swift
//  FileAuditSystem
//
//  Created by Sebastián Benítez on 28/11/2022.
//

import Cocoa
import AuditCore

class ViewController: NSViewController {
    // MARK: - Outlets
    
    @IBOutlet private var tableView: NSTableView!
    @IBOutlet private var removeFoldersButton: NSButton!
    
    // MARK: - Properties
    
    var client: SecurityClient!
    
    // MARK: - Function Overrides
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        client = (NSApp.delegate as? AppDelegate)?.client
    }
    
    // MARK: - Actions
    
    @IBAction private func addFolder(_ sender: Any) {
        // Let the user pick a folder to monitor.
        let openPanel = NSOpenPanel()
        openPanel.canChooseDirectories = true
        openPanel.canChooseFiles = false
        if openPanel.runModal() == .OK,
           let url = openPanel.urls.first,
           !client.monitoredFolders.contains(url) {
            // Add selected folder to the client's monitored folders.
            client.monitoredFolders.append(url)
            tableView.reloadData()
        }
    }
    
    @IBAction private func removeFolders(_ sender: Any) {
        client.monitoredFolders.remove(at: tableView.selectedRowIndexes)
        client.monitoredFolders = client.monitoredFolders
        
        tableView.reloadData()
    }
}

extension ViewController: NSTableViewDataSource {
    func numberOfRows(in tableView: NSTableView) -> Int {
        return client.monitoredFolders.count
    }
    
    func tableView(_ tableView: NSTableView,
                   objectValueFor tableColumn: NSTableColumn?,
                   row: Int) -> Any? {
        return client.monitoredFolders[row].path
    }
}

extension ViewController: NSTableViewDelegate {
    func tableViewSelectionDidChange(_ notification: Notification) {
        removeFoldersButton.isEnabled = tableView.selectedRowIndexes.count > 0
    }
}
