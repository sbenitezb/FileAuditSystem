//
//  Array+Extensions.swift
//  FileAuditSystem
//
//  Created by Sebastián Benítez on 29/11/2022.
//

import Foundation

// Taken from https://stackoverflow.com/questions/26173565/removeobjectsatindexes-for-swift-arrays

extension Array {
    mutating func remove(at set:IndexSet) {
        var arr = Swift.Array(self.enumerated())
        arr.removeAll{set.contains($0.offset)}
        self = arr.map{$0.element}
    }
}
