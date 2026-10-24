import Foundation
import AppKit
import SwiftUI

enum MetadataCategory: String, CaseIterable, Identifiable, Codable, Sendable {
    case privacy = "Privacy & Security"
    case file = "File"
    case format = "Content"
    case integrity = "Integrity"
    case system = "macOS"
    case provenance = "Provenance"
    case structure = "Structure"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .privacy: "shield.lefthalf.filled"
        case .file: "doc.text"
        case .format: "viewfinder"
        case .integrity: "checkmark.seal"
        case .system: "macwindow"
        case .provenance: "point.3.connected.trianglepath.dotted"
        case .structure: "square.3.layers.3d"
        }
    }

    var tint: Color {
        switch self {
        case .privacy: TraceTheme.coral
        case .file: TraceTheme.blue
        case .format: TraceTheme.mint
        case .integrity: TraceTheme.blue
        case .system: TraceTheme.amber
        case .provenance: TraceTheme.indigo
        case .structure: TraceTheme.indigo
        }
    }
}

enum ScanMode: String, CaseIterable, Identifiable, Sendable {
    case basic = "Basic"
    case advanced = "Advanced"

    var id: Self { self }

    var description: String {
        switch self {
        case .basic: "Fast metadata overview"
        case .advanced: "Deep, safe read-only inspection"
        }
    }
}

struct MetadataItem: Identifiable, Hashable, Sendable {
    let id: UUID
    let label: String
    let value: String
    let category: MetadataCategory
    let isSensitive: Bool
    let explanation: String?

    init(
        _ label: String,
        _ value: String,
        category: MetadataCategory,
        sensitive: Bool = false,
        explanation: String? = nil
    ) {
        id = UUID()
        self.label = label
        self.value = value
        self.category = category
        isSensitive = sensitive
        self.explanation = explanation
    }
}

enum FindingSeverity: Int, CaseIterable, Comparable, Sendable {
    case info = 0
    case low = 1
    case medium = 2
    case high = 3

    static func < (lhs: FindingSeverity, rhs: FindingSeverity) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    var title: String {
        switch self {
        case .info: "Info"
        case .low: "Low"
        case .medium: "Medium"
        case .high: "High"
        }
    }

    var color: Color {
        switch self {
        case .info: TraceTheme.blue
        case .low: TraceTheme.mint
        case .medium: TraceTheme.amber
        case .high: TraceTheme.coral
        }
    }
}

struct PrivacyFinding: Identifiable, Hashable, Sendable {
    let id = UUID()
    let title: String
    let detail: String
    let severity: FindingSeverity
    let icon: String
}

struct ScanResult: Identifiable, Sendable {
    let id = UUID()
    let url: URL
    let scannedAt: Date
    let contentType: String
    let typeIcon: String
    let fileSize: Int64
    let items: [MetadataItem]
    let findings: [PrivacyFinding]
    let elapsed: Duration
    let mode: ScanMode

    var name: String { url.lastPathComponent }
    var sensitiveCount: Int { items.filter(\.isSensitive).count }
    var highestSeverity: FindingSeverity { findings.map(\.severity).max() ?? .info }

    func items(in category: MetadataCategory) -> [MetadataItem] {
        items.filter { $0.category == category }
    }
}

enum ScanPhase: Equatable {
    case idle
    case scanning(URL)
    case result
    case failed(String)
}

struct RecentScan: Identifiable {
    let id = UUID()
    let name: String
    let url: URL
    let date: Date
    let severity: FindingSeverity
    let icon: String
}

enum TraceTheme {
    static let ink = Color(nsColor: .windowBackgroundColor)
    static let panel = Color(nsColor: .controlBackgroundColor)
    static let raised = Color(nsColor: .unemphasizedSelectedContentBackgroundColor)
    static let mint = Color.accentColor
    static let blue = Color.blue
    static let coral = Color.orange
    static let amber = Color.orange
    static let indigo = Color.purple
    static let secondaryText = Color(nsColor: .secondaryLabelColor)
    static let divider = Color(nsColor: .separatorColor)
}

extension Int64 {
    var traceFileSize: String {
        ByteCountFormatter.string(fromByteCount: self, countStyle: .file)
    }
}

extension Duration {
    var traceMilliseconds: String {
        let components = self.components
        let value = Double(components.seconds) * 1_000
            + Double(components.attoseconds) / 1_000_000_000_000_000
        return String(format: "%.0f ms", value)
    }
}
