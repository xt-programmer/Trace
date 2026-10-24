import AppKit
import Foundation
import Observation
import UniformTypeIdentifiers

@MainActor
@Observable
final class ScanStore {
    var phase: ScanPhase = .idle
    var result: ScanResult?
    var mode: ScanMode = .basic
    var selectedCategory: MetadataCategory = .privacy
    var recents: [RecentScan] = []
    var isDropTargeted = false

    private let scanner = BasicScanner()
    private let advancedScanner = AdvancedScanner()
    private var scanTask: Task<Void, Never>?

    func chooseFile() {
        let panel = NSOpenPanel()
        panel.title = "Choose a file to inspect"
        panel.prompt = "Inspect File"
        panel.message = "Trace reads the file locally. Nothing is uploaded."
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = [.item]

        guard panel.runModal() == .OK, let url = panel.url else { return }
        inspect(url)
    }

    func inspect(_ url: URL) {
        scanTask?.cancel()
        result = nil
        guard url.isFileURL else {
            phase = .failed("Trace can only inspect local files.")
            return
        }
        phase = .scanning(url)
        selectedCategory = .privacy

        let selectedMode = mode
        scanTask = Task {
            do {
                let scan: ScanResult
                switch selectedMode {
                case .basic:
                    scan = try await scanner.scan(url: url)
                case .advanced:
                    scan = try await advancedScanner.scan(url: url)
                }
                guard !Task.isCancelled, mode == selectedMode else { return }
                result = scan
                phase = .result
                recents.removeAll { $0.url == scan.url }
                recents.insert(
                    .init(name: scan.name, url: scan.url, date: scan.scannedAt,
                          severity: scan.highestSeverity, icon: scan.typeIcon),
                    at: 0
                )
                recents = Array(recents.prefix(8))
            } catch {
                guard !Task.isCancelled else { return }
                phase = .failed(error.localizedDescription)
            }
        }
    }

    func setMode(_ newMode: ScanMode) {
        guard mode != newMode else { return }
        mode = newMode
        if let currentURL = result?.url {
            inspect(currentURL)
        } else if case .scanning(let currentURL) = phase {
            inspect(currentURL)
        }
    }

    func reset() {
        scanTask?.cancel()
        result = nil
        phase = .idle
        selectedCategory = .privacy
    }

    func revealInFinder() {
        guard let result else { return }
        NSWorkspace.shared.activateFileViewerSelecting([result.url])
    }

    func copyReport() {
        guard let result else { return }
        var lines = [
            "TRACE \(result.mode.rawValue.uppercased()) SCAN",
            result.name,
            "\(result.contentType) • \(result.fileSize.traceFileSize)",
            "Scanned \(result.scannedAt.formatted(date: .abbreviated, time: .standard))",
            "",
            "PRIVACY & SECURITY"
        ]
        lines.append(contentsOf: result.findings.map {
            "[\($0.severity.title.uppercased())] \($0.title): \($0.detail)"
        })
        for category in MetadataCategory.allCases where category != .privacy {
            lines.append("")
            lines.append(category.rawValue.uppercased())
            lines.append(contentsOf: result.items(in: category).map { "\($0.label): \($0.value)" })
        }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(lines.joined(separator: "\n"), forType: .string)
    }
}
