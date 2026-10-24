import Foundation

@main
enum ScannerSmoke {
    static func main() async throws {
        let fixture = FileManager.default.temporaryDirectory
            .appending(path: "trace-smoke-\(UUID().uuidString).txt")
        let content = "Trace sees metadata.\nLocally and quickly.\n"
        try content.write(to: fixture, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: fixture) }

        let result = try await BasicScanner().scan(url: fixture)
        let fieldSummary = result.items.map { "\($0.label)=\($0.value)" }.joined(separator: ", ")
        precondition(result.fileSize == Int64(content.utf8.count), "Incorrect file size")
        precondition(
            result.items.contains { $0.label == "Text encoding" && $0.value == "UTF-8" },
            "Text encoding was not detected. Fields: \(fieldSummary)"
        )
        precondition(
            result.items.contains { $0.label == "Lines" && $0.value == "2" },
            "Line count was not detected"
        )
        precondition(
            result.items.contains { $0.label == "POSIX permissions" },
            "Permissions were not detected"
        )

        // Exercise both sides of the Basic scanner's one-megabyte text limit.
        try Data(repeating: 65, count: 1_000_000).write(to: fixture)
        let boundary = try await BasicScanner().scan(url: fixture)
        precondition(boundary.items.contains {
            $0.label == "Text scan coverage" && $0.value == "Entire file"
        }, "Exact-limit file was incorrectly labeled as sampled")

        try Data(repeating: 65, count: 1_000_001).write(to: fixture)
        let sampled = try await BasicScanner().scan(url: fixture)
        precondition(sampled.items.contains { $0.label == "Lines (sampled)" },
                     "Large-file line count was not labeled as sampled")
        precondition(!sampled.items.contains { $0.label == "Lines" },
                     "Sampled line count was presented as a whole-file count")

        let advancedContent = """
        contact: privacy@example.com
        api_key = value-hidden-by-report
        """
        try advancedContent.write(to: fixture, atomically: true, encoding: .utf8)
        let advanced = try await AdvancedScanner().scan(url: fixture)

        precondition(advanced.mode == .advanced, "Advanced mode was not recorded")
        precondition(
            advanced.items.contains { $0.label == "SHA-256" && $0.value.count == 64 },
            "SHA-256 was not calculated"
        )
        precondition(
            advanced.items.contains { $0.label == "Email addresses" && $0.isSensitive },
            "Embedded email address was not highlighted"
        )
        precondition(
            advanced.findings.contains { $0.title == "Possible credential or secret" },
            "Possible secret marker was not reported"
        )

        let archiveFixture = FileManager.default.temporaryDirectory
            .appending(path: "trace-archive-\(UUID().uuidString).zip")
        try makeEmptyZIP(entryName: "../escape.txt").write(to: archiveFixture)
        defer { try? FileManager.default.removeItem(at: archiveFixture) }
        let archive = try await AdvancedScanner().scan(url: archiveFixture)
        precondition(
            archive.items.contains { $0.label == "Entries inventoried" && $0.value == "1" },
            "ZIP central directory was not inventoried"
        )
        precondition(
            archive.findings.contains { $0.title == "Unsafe archive paths" },
            "Unsafe ZIP path was not reported"
        )

        print(
            "Scanner smoke test passed: Basic \(result.items.count) fields; " +
            "Advanced \(advanced.items.count) fields; safe ZIP inventory passed"
        )
    }

    private static func makeEmptyZIP(entryName: String) -> Data {
        let name = Data(entryName.utf8)
        var local = Data()
        local.appendLE(UInt32(0x04034B50))
        local.appendLE(UInt16(20))
        local.appendLE(UInt16(0))
        local.appendLE(UInt16(0))
        local.appendLE(UInt16(0))
        local.appendLE(UInt16(0))
        local.appendLE(UInt32(0))
        local.appendLE(UInt32(0))
        local.appendLE(UInt32(0))
        local.appendLE(UInt16(name.count))
        local.appendLE(UInt16(0))
        local.append(name)

        var central = Data()
        central.appendLE(UInt32(0x02014B50))
        central.appendLE(UInt16(20))
        central.appendLE(UInt16(20))
        central.appendLE(UInt16(0))
        central.appendLE(UInt16(0))
        central.appendLE(UInt16(0))
        central.appendLE(UInt16(0))
        central.appendLE(UInt32(0))
        central.appendLE(UInt32(0))
        central.appendLE(UInt32(0))
        central.appendLE(UInt16(name.count))
        central.appendLE(UInt16(0))
        central.appendLE(UInt16(0))
        central.appendLE(UInt16(0))
        central.appendLE(UInt16(0))
        central.appendLE(UInt32(0))
        central.appendLE(UInt32(0))
        central.append(name)

        var end = Data()
        end.appendLE(UInt32(0x06054B50))
        end.appendLE(UInt16(0))
        end.appendLE(UInt16(0))
        end.appendLE(UInt16(1))
        end.appendLE(UInt16(1))
        end.appendLE(UInt32(central.count))
        end.appendLE(UInt32(local.count))
        end.appendLE(UInt16(0))
        return local + central + end
    }
}

private extension Data {
    mutating func appendLE<T: FixedWidthInteger>(_ value: T) {
        var littleEndian = value.littleEndian
        Swift.withUnsafeBytes(of: &littleEndian) { append(contentsOf: $0) }
    }
}
