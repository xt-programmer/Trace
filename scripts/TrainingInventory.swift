import Foundation

@main
enum TrainingInventory {
    static func main() async throws {
        let folder = URL(fileURLWithPath: CommandLine.arguments.dropFirst().first ?? "Training")
        let urls = try FileManager.default.contentsOfDirectory(
            at: folder,
            includingPropertiesForKeys: [.isRegularFileKey],
            options: [.skipsHiddenFiles]
        )
        .filter { (try? $0.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true }
        .sorted { $0.lastPathComponent.localizedStandardCompare($1.lastPathComponent) == .orderedAscending }

        for url in urls {
            let result = try await AdvancedScanner().scan(url: url)
            print("\n=== \(result.name) ===")
            print("\(result.contentType) | \(result.fileSize.traceFileSize) | \(result.items.count) fields")
            for finding in result.findings {
                print("! [\(finding.severity.title)] \(finding.title): \(finding.detail)")
            }
            for category in MetadataCategory.allCases where category != .privacy {
                let categoryItems = result.items(in: category)
                guard !categoryItems.isEmpty else { continue }
                print("-- \(category.rawValue)")
                for item in categoryItems {
                    let value = item.value
                        .replacingOccurrences(of: "\n", with: " | ")
                        .prefix(220)
                    print("\(item.isSensitive ? "* " : "  ")\(item.label): \(value)")
                }
            }
        }
    }
}
