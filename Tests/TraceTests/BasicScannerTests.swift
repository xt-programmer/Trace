import Foundation
import Testing
@testable import Trace

struct BasicScannerTests {
    @Test
    func scansTextMetadata() async throws {
        let url = FileManager.default.temporaryDirectory
            .appending(path: "trace-test-\(UUID().uuidString).txt")
        let content = "Trace sees metadata.\nLocally and quickly.\n"
        try content.write(to: url, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: url) }

        let result = try await BasicScanner().scan(url: url)

        #expect(result.fileSize == Int64(content.utf8.count))
        #expect(result.items.contains { $0.label == "Text encoding" && $0.value == "UTF-8" })
        #expect(result.items.contains { $0.label == "Lines" && $0.value == "2" })
        #expect(result.items.contains { $0.label == "POSIX permissions" })
    }

    @Test
    func flagsWorldWritableFile() async throws {
        let url = FileManager.default.temporaryDirectory
            .appending(path: "trace-permissions-\(UUID().uuidString).txt")
        try Data("test".utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o666], ofItemAtPath: url.path)
        defer { try? FileManager.default.removeItem(at: url) }

        let result = try await BasicScanner().scan(url: url)

        #expect(result.findings.contains { $0.title == "World-writable permissions" })
    }

    @Test
    func advancedScanHashesAndHighlightsIdentifiers() async throws {
        let url = FileManager.default.temporaryDirectory
            .appending(path: "trace-advanced-\(UUID().uuidString).txt")
        try Data("contact privacy@example.com\napi_key = hidden\n".utf8).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let result = try await AdvancedScanner().scan(url: url)

        #expect(result.mode == .advanced)
        #expect(result.items.contains { $0.label == "SHA-256" && $0.value.count == 64 })
        #expect(result.items.contains { $0.label == "Email addresses" && $0.isSensitive })
        #expect(result.findings.contains { $0.title == "Possible credential or secret" })
    }

    @Test
    func labelsLargeTextAsSampled() async throws {
        let url = FileManager.default.temporaryDirectory
            .appending(path: "trace-sampling-\(UUID().uuidString).txt")
        try Data(repeating: 65, count: 1_000_001).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let result = try await BasicScanner().scan(url: url)

        #expect(result.fileSize == 1_000_001)
        #expect(result.items.contains { $0.label == "Lines (sampled)" })
        #expect(!result.items.contains { $0.label == "Lines" })
        #expect(result.items.contains {
            $0.label == "Text scan coverage" && $0.value == "First 1,000,000 bytes (sampled)"
        })
    }

    @Test
    func reportsExactSamplingBoundaryAsComplete() async throws {
        let url = FileManager.default.temporaryDirectory
            .appending(path: "trace-boundary-\(UUID().uuidString).txt")
        try Data(repeating: 65, count: 1_000_000).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        let result = try await BasicScanner().scan(url: url)

        #expect(result.items.contains { $0.label == "Lines" && $0.value == "1" })
        #expect(result.items.contains { $0.label == "Text scan coverage" && $0.value == "Entire file" })
    }

}
