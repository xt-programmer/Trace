import CryptoKit
import Foundation
import ImageIO
import PDFKit
import Security
import UniformTypeIdentifiers
import Darwin

struct AdvancedScanner: Sendable {
    private let privacySampleLimit = 32 * 1_024 * 1_024
    private let archiveDirectoryLimit = 32 * 1_024 * 1_024

    func scan(url: URL) async throws -> ScanResult {
        let clock = ContinuousClock()
        let start = clock.now
        let accessGranted = url.startAccessingSecurityScopedResource()
        defer {
            if accessGranted { url.stopAccessingSecurityScopedResource() }
        }

        let basic = try await BasicScanner().scan(url: url)
        var items = basic.items
        var findings = basic.findings.filter { $0.title != "No obvious sensitive fields" }

        let integrity = try inspectIntegrity(at: url)
        items.append(contentsOf: integrity.items)
        findings.append(contentsOf: integrity.findings)

        let privacy = inspectEmbeddedIdentifiers(at: url)
        items.append(contentsOf: privacy.items)
        findings.append(contentsOf: privacy.findings)

        let localProvenance = inspectLocalProvenance(at: url)
        items.append(contentsOf: localProvenance.items)
        findings.append(contentsOf: localProvenance.findings)

        if isImage(url) {
            let image = inspectAllImageMetadata(at: url, existing: items)
            items.append(contentsOf: image.items)
            findings.append(contentsOf: image.findings)
        }

        if url.pathExtension.lowercased() == "pdf" {
            let pdf = inspectPDF(at: url)
            items.append(contentsOf: pdf.items)
            findings.append(contentsOf: pdf.findings)
        }

        if url.pathExtension.lowercased() == "stl" {
            let model = inspectSTL(at: url)
            items.append(contentsOf: model.items)
            findings.append(contentsOf: model.findings)
        }

        if url.pathExtension.lowercased() == "gcode" {
            let toolpath = inspectGCode(at: url)
            items.append(contentsOf: toolpath.items)
            findings.append(contentsOf: toolpath.findings)
        }

        let archive = inspectArchive(at: url)
        items.append(contentsOf: archive.items)
        findings.append(contentsOf: archive.findings)

        if integrity.isExecutable {
            let signing = inspectCodeSigning(at: url)
            items.append(contentsOf: signing.items)
            findings.append(contentsOf: signing.findings)
        }

        if findings.isEmpty {
            findings.append(.init(
                title: "No obvious sensitive fields",
                detail: "The Advanced scan found no high-signal privacy or security metadata.",
                severity: .info,
                icon: "checkmark.shield.fill"
            ))
        }

        return ScanResult(
            url: basic.url,
            scannedAt: .now,
            contentType: basic.contentType,
            typeIcon: basic.typeIcon,
            fileSize: basic.fileSize,
            items: deduplicated(items),
            findings: deduplicated(findings).sorted { $0.severity > $1.severity },
            elapsed: start.duration(to: clock.now),
            mode: .advanced
        )
    }

    // MARK: - Whole-file integrity

    private func inspectIntegrity(at url: URL) throws -> IntegrityReport {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }

        var sha256 = SHA256()
        var sha1 = Insecure.SHA1()
        var md5 = Insecure.MD5()
        var frequencies = [UInt64](repeating: 0, count: 256)
        var totalBytes: UInt64 = 0
        var firstBytes = Data()
        var lastBytes = Data()

        while let chunk = try handle.read(upToCount: 1_048_576), !chunk.isEmpty {
            try Task.checkCancellation()
            if firstBytes.count < 512 {
                firstBytes.append(chunk.prefix(512 - firstBytes.count))
            }
            if chunk.count >= 512 {
                lastBytes = Data(chunk.suffix(512))
            } else {
                lastBytes.append(chunk)
                if lastBytes.count > 512 { lastBytes.removeFirst(lastBytes.count - 512) }
            }
            sha256.update(data: chunk)
            sha1.update(data: chunk)
            md5.update(data: chunk)
            totalBytes += UInt64(chunk.count)
            for byte in chunk { frequencies[Int(byte)] += 1 }
        }

        let signature = detectedSignature(
            firstBytes,
            lastBytes: lastBytes,
            fileExtension: url.pathExtension.lowercased(),
            fileSize: totalBytes
        )
        let extensionMatches = signatureMatchesExtension(signature, extension: url.pathExtension.lowercased())
        let executable = isExecutableSignature(signature)
            || (signature.name == FileSignature.unknown.name && hasExecutePermission(url))
        let entropy = shannonEntropy(frequencies: frequencies, count: totalBytes)
        var items: [MetadataItem] = [
            .init("SHA-256", hex(sha256.finalize()), category: .integrity),
            .init("SHA-1", hex(sha1.finalize()), category: .integrity),
            .init("MD5", hex(md5.finalize()), category: .integrity),
            .init("Detected signature", signature.name, category: .integrity),
            .init("Extension consistency", extensionMatches == nil ? "Not enough information" : (extensionMatches! ? "Matches content" : "Does not match content"), category: .integrity),
            .init("Shannon entropy", String(format: "%.4f bits per byte", entropy), category: .integrity),
            .init("Bytes analyzed", Int64(totalBytes).traceFileSize, category: .integrity),
            .init("Safety policy", executable
                  ? "Inspected strictly as data — never launched"
                  : "Read-only inspection — file was never modified",
                  category: .integrity)
        ]
        var findings: [PrivacyFinding] = []

        if extensionMatches == false {
            findings.append(.init(
                title: "Extension does not match file contents",
                detail: "The filename suggests a different format than the file signature.",
                severity: .high,
                icon: "doc.badge.ellipsis"
            ))
        }
        if entropy > 7.85, totalBytes > 4_096, !normallyHighEntropy(signature) {
            items.append(.init("High-entropy content", "Detected", category: .integrity))
            findings.append(.init(
                title: "High-entropy content",
                detail: "The file appears heavily compressed, encrypted, or unusually randomized.",
                severity: .info,
                icon: "waveform.path.ecg"
            ))
        }
        if executable {
            findings.append(.init(
                title: "Executable content handled safely",
                detail: "Trace inspected headers and signing data without launching the file.",
                severity: .info,
                icon: "checkmark.shield"
            ))
        }
        return IntegrityReport(items: items, findings: findings, isExecutable: executable)
    }

    // MARK: - Identifiers and possible secrets

    private func inspectEmbeddedIdentifiers(at url: URL) -> InspectionReport {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return .empty }
        defer { try? handle.close() }
        let data = (try? handle.read(upToCount: privacySampleLimit)) ?? Data()
        guard !data.isEmpty else { return .empty }

        let isLikelyText = String(data: data, encoding: .utf8) != nil
        let searchable: String
        if let utf8 = String(data: data, encoding: .utf8) {
            searchable = utf8
        } else {
            let bytes = data.map { byte -> UInt8 in
                (byte == 9 || byte == 10 || byte == 13 || (32...126).contains(byte)) ? byte : 32
            }
            searchable = String(decoding: bytes, as: UTF8.self)
        }

        let inspectIdentifiers = isTextualPrivacyTarget(url)
        let emails = inspectIdentifiers
            ? matches(#"(?i)\b[A-Z0-9._%+\-]{2,}@[A-Z0-9\-]{2,}(?:\.[A-Z0-9\-]{2,})+\b"#, in: searchable)
            : []
        let addresses = inspectIdentifiers
            ? matches(#"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"#, in: searchable)
            : []
        let urls = matches(#"(?i)\bhttps?://[^\s<>"']+"#, in: searchable)
        let localPaths = inspectIdentifiers
            ? matches(#"(?:/Users/|/home/)[A-Za-z0-9._\-]+(?:/[^\s"'<>]+)?"#, in: searchable)
            : []
        let secretAssignments = inspectIdentifiers
            ? matches(
                #"(?i)\b(?:api[_\-]?key|access[_\-]?token|auth[_\-]?token|client[_\-]?secret|password|passwd)\b\s*[:=]"#,
                in: searchable
            )
            : []
        let zeroWidthCount = inspectIdentifiers
            ? searchable.unicodeScalars.reduce(into: 0) { count, scalar in
                if [0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF].contains(scalar.value) { count += 1 }
            }
            : 0

        var items: [MetadataItem] = [
            .init(
                "Identifier scan coverage",
                data.count == privacySampleLimit
                    ? "First \(Int64(data.count).traceFileSize) (safety limit)"
                    : "Entire file (\(Int64(data.count).traceFileSize))",
                category: .integrity
            )
        ]
        var findings: [PrivacyFinding] = []

        let lowercased = searchable.lowercased()
        let hasC2PA = lowercased.contains("c2pa")
            && (lowercased.contains("jumb") || lowercased.contains("c2pa.claim") || lowercased.contains("c2pa.actions"))
        let declaresGeneratedMedia = lowercased.contains("trainedalgorithmicmedia")
            || lowercased.contains("containsaigeneratedcontent")
        if hasC2PA {
            items.append(.init("Content Credentials (C2PA)", "Manifest markers present", category: .provenance))
            items.append(.init("Credential validation", "Signature marker present; cryptographic trust not validated by this build", category: .integrity))
            if lowercased.contains("gpt-image") {
                items.append(.init("Provenance software agent", "gpt-image", category: .provenance))
            }
            if lowercased.contains("openai media service api") {
                items.append(.init("Claim generator", "OpenAI Media Service API", category: .provenance))
            }
        }
        if declaresGeneratedMedia {
            items.append(.init("AI-generated content declaration", "Present", category: .provenance))
            findings.append(.init(
                title: "AI-generated provenance declared",
                detail: "Embedded provenance metadata identifies the content as generated or modified by an algorithmic system.",
                severity: .info,
                icon: "wand.and.stars"
            ))
        }

        if !emails.isEmpty {
            items.append(.init("Email addresses", emails.joined(separator: "\n"), category: .format, sensitive: true,
                               explanation: "Embedded addresses can directly identify people or accounts."))
            findings.append(.init(
                title: "Email address embedded",
                detail: "\(emails.count) unique email address\(emails.count == 1 ? "" : "es") found in readable file data.",
                severity: .high,
                icon: "envelope.badge.fill"
            ))
        }
        if !addresses.isEmpty {
            items.append(.init("IP addresses", addresses.joined(separator: "\n"), category: .format, sensitive: true,
                               explanation: "Network addresses can reveal infrastructure or approximate origin."))
            findings.append(.init(
                title: "Network address embedded",
                detail: "\(addresses.count) unique IPv4 address\(addresses.count == 1 ? "" : "es") found.",
                severity: .medium,
                icon: "network"
            ))
        }
        if !localPaths.isEmpty {
            items.append(.init("Embedded local paths", localPaths.joined(separator: "\n"), category: .format, sensitive: true,
                               explanation: "Unlike the filesystem path, these paths are stored inside the file."))
            findings.append(.init(
                title: "Local path embedded in content",
                detail: "Stored path text may expose a username or directory structure when shared.",
                severity: .high,
                icon: "folder.badge.person.crop"
            ))
        }
        if !urls.isEmpty {
            items.append(.init("Embedded URLs", urls.joined(separator: "\n"), category: .structure,
                               explanation: "External references may reveal sources or related services."))
        }
        if !secretAssignments.isEmpty {
            items.append(.init("Possible secret assignments", "\(secretAssignments.count) marker(s); values intentionally hidden", category: .format, sensitive: true,
                               explanation: "Trace does not display the possible secret values in its report."))
            findings.append(.init(
                title: "Possible credential or secret",
                detail: "A key, token, secret, or password assignment marker was found. Its value is intentionally hidden.",
                severity: .high,
                icon: "key.fill"
            ))
        }
        if zeroWidthCount > 0 {
            items.append(.init("Invisible Unicode characters", "\(zeroWidthCount) zero-width character(s)", category: .format))
            findings.append(.init(
                title: "Invisible text content",
                detail: "Zero-width Unicode characters can carry hidden information or disguise text.",
                severity: .medium,
                icon: "eye.slash.fill"
            ))
        }
        if isLikelyText {
            items.append(.init("Readable content model", "Valid UTF-8", category: .integrity))
        }
        return InspectionReport(items: items, findings: findings)
    }

    // MARK: - Deep image metadata

    private func inspectAllImageMetadata(at url: URL, existing: [MetadataItem]) -> InspectionReport {
        guard let source = CGImageSourceCreateWithURL(url as CFURL, nil) else { return .empty }
        let frameCount = CGImageSourceGetCount(source)
        var items = [MetadataItem("Image frame count", String(frameCount), category: .structure)]
        let existingPairs = Set(existing.map { "\($0.label)|\($0.value)" })
        let frameLimit = min(frameCount, 100)

        for index in 0..<frameLimit {
            guard let properties = CGImageSourceCopyPropertiesAtIndex(source, index, nil) as? [AnyHashable: Any] else {
                continue
            }
            var flattened: [(String, String)] = []
            flatten(properties, prefix: frameCount > 1 ? "Frame \(index + 1)" : "", into: &flattened)
            for (key, value) in flattened.prefix(500 - min(items.count, 500)) {
                let label = "Metadata • \(key)"
                guard !existingPairs.contains("\(label)|\(value)") else { continue }
                let sensitive = isSensitiveMetadataKey(key)
                items.append(.init(
                    label,
                    value,
                    category: .format,
                    sensitive: sensitive,
                    explanation: sensitive ? "This raw metadata field may identify a person, place, device, or editing workflow." : nil
                ))
                if items.count >= 500 { break }
            }
            if items.count >= 500 { break }
        }
        if frameCount > frameLimit {
            items.append(.init("Frame metadata limit", "Inspected first \(frameLimit) of \(frameCount) frames", category: .structure))
        }

        let sensitiveCount = items.filter(\.isSensitive).count
        let findings: [PrivacyFinding] = sensitiveCount > 0 ? [
            .init(
                title: "Additional identifying image metadata",
                detail: "\(sensitiveCount) sensitive raw field\(sensitiveCount == 1 ? "" : "s") found during deep metadata enumeration.",
                severity: .medium,
                icon: "photo.badge.exclamationmark"
            )
        ] : []
        return InspectionReport(items: items, findings: findings)
    }

    // MARK: - Local Photos provenance

    private func inspectLocalProvenance(at url: URL) -> InspectionReport {
        let fields: [(String, String, Bool)] = [
            ("com.apple.assetsd.originalFilename", "Photos original filename", false),
            ("com.apple.assetsd.creatorBundleID", "Capture application", false),
            ("com.apple.assetsd.importedByDisplayName", "Imported by", false),
            ("com.apple.assetsd.timeZoneName", "Capture time zone", true),
            ("com.apple.assetsd.addedDate", "Added to Photos", true),
            ("com.apple.assetsd.customCreationDate", "Photos creation date", true),
            ("com.apple.assetsd.dbRebuildUuid", "Photos library identifier", true),
            ("com.apple.assetsd.UUID", "Photos asset identifier", true)
        ]
        var items: [MetadataItem] = []
        for (attribute, label, sensitive) in fields {
            guard let data = readXattr(attribute, at: url),
                  let value = displayXattr(data, identifier: attribute), !value.isEmpty else { continue }
            items.append(.init(
                label,
                value,
                category: .provenance,
                sensitive: sensitive,
                explanation: sensitive ? "This Photos-library value may reveal timing or correlate the asset across copies." : nil
            ))
        }
        let findings: [PrivacyFinding] = items.contains(where: { $0.label == "Photos asset identifier" || $0.label == "Photos library identifier" }) ? [
            .init(
                title: "Photos-library identifiers retained",
                detail: "Extended attributes contain stable identifiers from the local Photos library.",
                severity: .medium,
                icon: "photo.badge.exclamationmark"
            )
        ] : []
        return InspectionReport(items: items, findings: findings)
    }

    private func readXattr(_ name: String, at url: URL) -> Data? {
        let size = getxattr(url.path, name, nil, 0, 0, XATTR_NOFOLLOW)
        guard size > 0 else { return nil }
        var bytes = [UInt8](repeating: 0, count: size)
        let count = getxattr(url.path, name, &bytes, bytes.count, 0, XATTR_NOFOLLOW)
        guard count > 0 else { return nil }
        return Data(bytes.prefix(count))
    }

    private func displayXattr(_ data: Data, identifier: String) -> String? {
        if let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) {
            if let date = plist as? Date {
                return date.formatted(date: .abbreviated, time: .standard)
            }
            if let string = plist as? String { return string }
            if let number = plist as? NSNumber { return number.stringValue }
        }
        if let string = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .controlCharacters.union(.whitespacesAndNewlines)),
           !string.isEmpty {
            return string
        }
        if identifier.hasSuffix("UUID"), data.count == 16 {
            let hex = data.map { String(format: "%02X", $0) }.joined()
            return "\(hex.prefix(8))-\(hex.dropFirst(8).prefix(4))-\(hex.dropFirst(12).prefix(4))-\(hex.dropFirst(16).prefix(4))-\(hex.dropFirst(20))"
        }
        return nil
    }

    // MARK: - Manufacturing files

    private func inspectSTL(at url: URL) -> InspectionReport {
        guard let handle = try? FileHandle(forReadingFrom: url),
              let fileSize = try? handle.seekToEnd() else { return .empty }
        defer { try? handle.close() }
        try? handle.seek(toOffset: 0)
        guard let header = try? handle.read(upToCount: 84), header.count >= 84 else { return .empty }

        if String(data: header.prefix(5), encoding: .ascii)?.lowercased() == "solid" {
            return inspectASCIISTL(at: url)
        }

        let declaredTriangles = UInt64(little32(header, 80))
        let expectedSize = 84 + declaredTriangles * 50
        let safeTriangles = min(declaredTriangles, fileSize >= 84 ? (fileSize - 84) / 50 : 0, 5_000_000)
        var minimum = (x: Double.infinity, y: Double.infinity, z: Double.infinity)
        var maximum = (x: -Double.infinity, y: -Double.infinity, z: -Double.infinity)

        for _ in 0..<safeTriangles {
            guard let record = try? handle.read(upToCount: 50), record.count == 50 else { break }
            for offset in [12, 24, 36] {
                let x = Double(Float(bitPattern: little32(record, offset)))
                let y = Double(Float(bitPattern: little32(record, offset + 4)))
                let z = Double(Float(bitPattern: little32(record, offset + 8)))
                guard x.isFinite, y.isFinite, z.isFinite else { continue }
                minimum = (min(minimum.x, x), min(minimum.y, y), min(minimum.z, z))
                maximum = (max(maximum.x, x), max(maximum.y, y), max(maximum.z, z))
            }
        }

        let headerText = String(data: header.prefix(80), encoding: .ascii)?
            .trimmingCharacters(in: .controlCharacters.union(.whitespacesAndNewlines))
        var items: [MetadataItem] = [
            .init("STL encoding", "Binary", category: .format),
            .init("Triangle facets", String(declaredTriangles), category: .structure),
            .init("Structure consistency", expectedSize == fileSize ? "File size matches facet count" : "Declared facets and file size differ", category: .integrity),
            .init("Geometry bytes inspected", Int64(safeTriangles * 50).traceFileSize, category: .integrity)
        ]
        if let headerText, !headerText.isEmpty {
            items.append(.init("STL header", headerText, category: .format))
        }
        if minimum.x.isFinite {
            items.append(.init("Model bounds", formattedBounds(minimum: minimum, maximum: maximum), category: .format))
            items.append(.init(
                "Model dimensions",
                String(format: "%.3f × %.3f × %.3f units", maximum.x - minimum.x, maximum.y - minimum.y, maximum.z - minimum.z),
                category: .format
            ))
        }
        let findings: [PrivacyFinding] = expectedSize == fileSize ? [] : [
            .init(
                title: "Inconsistent STL structure",
                detail: "The declared triangle count does not match the available binary records.",
                severity: .medium,
                icon: "cube.transparent"
            )
        ]
        return InspectionReport(items: items, findings: findings)
    }

    private func inspectASCIISTL(at url: URL) -> InspectionReport {
        guard let data = try? Data(contentsOf: url, options: [.mappedIfSafe]),
              data.count <= 32 * 1_024 * 1_024,
              let text = String(data: data, encoding: .utf8) else {
            return InspectionReport(
                items: [.init("STL encoding", "ASCII (geometry scan skipped above 32 MB)", category: .format)],
                findings: []
            )
        }
        let facetRegex = try? NSRegularExpression(pattern: #"(?im)^\s*facet\s+normal\b"#)
        let facets = facetRegex?.numberOfMatches(
            in: text,
            range: NSRange(text.startIndex..<text.endIndex, in: text)
        ) ?? 0
        return InspectionReport(
            items: [
                .init("STL encoding", "ASCII", category: .format),
                .init("Triangle facets", String(facets), category: .structure)
            ],
            findings: []
        )
    }

    private func inspectGCode(at url: URL) -> InspectionReport {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return .empty }
        defer { try? handle.close() }
        let data = (try? handle.read(upToCount: 8 * 1_024 * 1_024)) ?? Data()
        guard let text = String(data: data, encoding: .utf8) else { return .empty }
        let lines = text.split(whereSeparator: \.isNewline)
        var items: [MetadataItem] = [
            .init("G-code lines inspected", String(lines.count), category: .structure)
        ]

        if let generated = lines.first(where: { $0.lowercased().contains("generated by") }) {
            let value = generated.drop(while: { $0 == ";" || $0.isWhitespace })
            items.append(.init("Toolpath generator", String(value), category: .provenance, sensitive: true,
                               explanation: "The generator record includes slicer version and may include an exact creation time."))
        }
        let interestingKeys = [
            "total layer number", "layer_height", "filament_density", "filament_diameter",
            "max_z_height", "nozzle_diameter", "filament used", "estimated printing time",
            "bed_temperature", "temperature", "printer_model", "printer_settings_id",
            "print_settings_id", "filament_settings_id"
        ]
        var seen = Set<String>()
        for line in lines.prefix(5_000) {
            let cleaned = line.drop(while: { $0 == ";" || $0.isWhitespace })
            guard let separator = cleaned.firstIndex(of: ":") else { continue }
            let key = cleaned[..<separator].trimmingCharacters(in: .whitespaces).lowercased()
            let value = cleaned[cleaned.index(after: separator)...].trimmingCharacters(in: .whitespaces)
            guard interestingKeys.contains(where: { key.contains($0) }), seen.insert(key).inserted else { continue }
            items.append(.init(key.replacingOccurrences(of: "_", with: " ").capitalized, value, category: .format))
        }
        let thumbnails = matches(#"(?im)thumbnail begin\s+(\d+x\d+)\s+\d+"#, in: text)
        if !thumbnails.isEmpty {
            items.append(.init("Embedded preview thumbnails", thumbnails.joined(separator: "\n"), category: .structure))
        }
        let movementCount = lines.reduce(into: 0) { count, line in
            let trimmed = line.drop(while: \.isWhitespace)
            if trimmed.hasPrefix("G0 ") || trimmed.hasPrefix("G1 ") { count += 1 }
        }
        items.append(.init("Movement commands", String(movementCount), category: .structure))
        let findings: [PrivacyFinding] = items.contains(where: { $0.label == "Toolpath generator" }) ? [
            .init(
                title: "Toolpath creation record",
                detail: "The G-code header identifies the slicer version and exact generation time.",
                severity: .medium,
                icon: "printer.fill"
            )
        ] : []
        return InspectionReport(items: items, findings: findings)
    }

    private func formattedBounds(
        minimum: (x: Double, y: Double, z: Double),
        maximum: (x: Double, y: Double, z: Double)
    ) -> String {
        String(
            format: "X %.3f…%.3f  •  Y %.3f…%.3f  •  Z %.3f…%.3f",
            minimum.x, maximum.x, minimum.y, maximum.y, minimum.z, maximum.z
        )
    }

    // MARK: - PDF

    private func inspectPDF(at url: URL) -> InspectionReport {
        guard let document = PDFDocument(url: url) else {
            return InspectionReport(
                items: [.init("PDF parser", "Document structure could not be read", category: .structure)],
                findings: []
            )
        }
        var items: [MetadataItem] = [
            .init("PDF pages", String(document.pageCount), category: .structure),
            .init("PDF encrypted", document.isEncrypted ? "Yes" : "No", category: .integrity),
            .init("PDF locked", document.isLocked ? "Yes" : "No", category: .integrity)
        ]
        var findings: [PrivacyFinding] = []
        if let rawData = try? Data(contentsOf: url, options: [.mappedIfSafe]) {
            let header = String(decoding: rawData.prefix(32), as: UTF8.self)
            if let version = header.range(of: #"%PDF-\d\.\d"#, options: .regularExpression) {
                items.append(.init("PDF version", String(header[version].dropFirst(5)), category: .structure))
            }
            let structuralText = String(decoding: rawData.prefix(32 * 1_024 * 1_024), as: UTF8.self)
            items.append(.init("Linearized for web", structuralText.contains("/Linearized") ? "Yes" : "No", category: .structure))
            items.append(.init("Tagged PDF", structuralText.contains("/Marked true") || structuralText.contains("/Marked>true") ? "Yes" : "No", category: .structure))
            if let language = firstCapture(#"/Lang\s*\(([^)]{1,64})\)"#, in: structuralText) {
                items.append(.init("Document language", language, category: .format))
            }
        }

        var pageSizes = Set<String>()
        var rotations = Set<Int>()
        var annotationCount = 0
        var textCharacters = 0
        for index in 0..<document.pageCount {
            guard let page = document.page(at: index) else { continue }
            let bounds = page.bounds(for: .mediaBox)
            pageSizes.insert(String(format: "%.0f × %.0f pt", bounds.width, bounds.height))
            rotations.insert(page.rotation)
            annotationCount += page.annotations.count
            textCharacters += page.string?.count ?? 0
        }
        if !pageSizes.isEmpty {
            items.append(.init("Page sizes", pageSizes.sorted().joined(separator: "\n"), category: .structure))
        }
        if !rotations.isEmpty {
            items.append(.init("Page rotations", rotations.sorted().map { "\($0)°" }.joined(separator: ", "), category: .structure))
        }
        items.append(.init("Annotations", String(annotationCount), category: .structure))
        items.append(.init("Extractable text", "\(textCharacters) characters", category: .structure))
        if let outline = document.outlineRoot {
            items.append(.init("Outline entries", String(outline.numberOfChildren), category: .structure))
        }
        if let attributes = document.documentAttributes {
            for (key, value) in attributes {
                let label = String(describing: key)
                    .replacingOccurrences(of: "PDFDocument", with: "")
                    .replacingOccurrences(of: "Attribute", with: "")
                let sensitive = isSensitiveMetadataKey(label)
                items.append(.init("PDF \(label)", String(describing: value), category: .format, sensitive: sensitive,
                                   explanation: sensitive ? "This descriptive field is embedded in the PDF." : nil))
            }
        }

        let markers = rawPDFMarkers(at: url)
        for marker in markers {
            items.append(.init("PDF active feature", marker, category: .structure))
        }
        if !markers.isEmpty {
            findings.append(.init(
                title: "PDF contains active or embedded features",
                detail: markers.joined(separator: ", ") + " detected. Trace did not open or execute them.",
                severity: .high,
                icon: "doc.badge.gearshape"
            ))
        }
        if document.isEncrypted {
            findings.append(.init(
                title: "Encrypted PDF",
                detail: document.isLocked
                    ? "Some contents cannot be inspected without a password."
                    : "The PDF uses encryption, although its readable structure was inspected.",
                severity: .medium,
                icon: "lock.doc.fill"
            ))
        }
        return InspectionReport(items: items, findings: findings)
    }

    // MARK: - Archives without extraction

    private func inspectArchive(at url: URL) -> InspectionReport {
        switch url.pathExtension.lowercased() {
        case "zip", "docx", "xlsx", "pptx", "epub", "jar":
            return inspectZIP(at: url)
        case "tar":
            return inspectTAR(at: url)
        case "dmg":
            return inspectDMG(at: url)
        case "gz", "gzip", "tgz", "bz2", "7z", "rar":
            return InspectionReport(
                items: [
                    .init("Archive handling", "Container recognized; payload was not decompressed", category: .structure),
                    .init("Extraction policy", "No files written and no embedded content executed", category: .integrity)
                ],
                findings: [
                    .init(
                        title: "Compressed payload not expanded",
                        detail: "Trace preserved archive boundaries to avoid exposing embedded data.",
                        severity: .info,
                        icon: "archivebox"
                    )
                ]
            )
        default:
            return .empty
        }
    }

    private func inspectDMG(at url: URL) -> InspectionReport {
        guard let handle = try? FileHandle(forReadingFrom: url),
              let fileSize = try? handle.seekToEnd(), fileSize >= 512 else { return .empty }
        defer { try? handle.close() }
        try? handle.seek(toOffset: fileSize - 512)
        guard let trailer = try? handle.read(upToCount: 512),
              trailer.count == 512,
              trailer.starts(with: Array("koly".utf8)) else {
            return InspectionReport(
                items: [.init("Disk image structure", "UDIF trailer not found", category: .structure)],
                findings: []
            )
        }

        let version = big32(trailer, 4)
        let flags = big32(trailer, 12)
        let dataForkLength = big64(trailer, 32)
        let resourceForkLength = big64(trailer, 48)
        let segmentNumber = big32(trailer, 56)
        let segmentCount = big32(trailer, 60)
        let dataChecksumType = big32(trailer, 80)
        let dataChecksumValue = big32(trailer, 88)
        let xmlOffset = big64(trailer, 216)
        let xmlLength = big64(trailer, 224)
        let masterChecksumType = big32(trailer, 352)
        let masterChecksumValue = big32(trailer, 360)
        let imageVariant = big32(trailer, 488)
        let sectorCount = big64(trailer, 492)
        let expandedBytes = sectorCount.multipliedReportingOverflow(by: 512)

        var items: [MetadataItem] = [
            .init("Disk image format", "UDIF (koly trailer)", category: .structure),
            .init("UDIF version", String(version), category: .structure),
            .init("UDIF flags", String(format: "0x%08X", flags), category: .structure),
            .init("Segments", "\(segmentNumber) of \(segmentCount)", category: .structure),
            .init("Compressed data fork", Int64(clamping: dataForkLength).traceFileSize, category: .structure),
            .init("Resource fork", Int64(clamping: resourceForkLength).traceFileSize, category: .structure),
            .init("Metadata property list", Int64(clamping: xmlLength).traceFileSize, category: .structure),
            .init("Sector count", String(sectorCount), category: .structure),
            .init("Declared expanded size", expandedBytes.overflow ? "Overflowed declared size" : Int64(clamping: expandedBytes.partialValue).traceFileSize, category: .structure),
            .init("Data checksum type", checksumName(dataChecksumType), category: .integrity),
            .init("Data checksum value", String(format: "%08X", dataChecksumValue), category: .integrity),
            .init("Master checksum type", checksumName(masterChecksumType), category: .integrity),
            .init("Master checksum value", String(format: "%08X", masterChecksumValue), category: .integrity),
            .init("Image variant", String(imageVariant), category: .structure),
            .init("Disk image handling", "Trailer and metadata read only — image was not mounted", category: .integrity)
        ]
        if !expandedBytes.overflow, expandedBytes.partialValue > 0 {
            items.append(.init(
                "Disk image compression ratio",
                String(format: "%.3f", Double(dataForkLength) / Double(expandedBytes.partialValue)),
                category: .structure
            ))
        }

        if xmlLength > 0, xmlLength <= 16 * 1_024 * 1_024,
           xmlOffset < fileSize, xmlOffset + xmlLength <= fileSize {
            try? handle.seek(toOffset: xmlOffset)
            if let plistData = try? handle.read(upToCount: Int(xmlLength)),
               let root = try? PropertyListSerialization.propertyList(from: plistData, options: [], format: nil) as? [String: Any],
               let resourceFork = root["resource-fork"] as? [String: Any],
               let blocks = resourceFork["blkx"] as? [[String: Any]] {
                let partitionNames = blocks.compactMap { block in
                    (block["Name"] as? String) ?? (block["CFName"] as? String)
                }
                items.append(.init("Partition descriptors", String(blocks.count), category: .structure))
                if !partitionNames.isEmpty {
                    items.append(.init("Partition names", partitionNames.joined(separator: "\n"), category: .structure))
                }
            }
        }
        return InspectionReport(items: items, findings: [])
    }

    private func inspectZIP(at url: URL) -> InspectionReport {
        guard let handle = try? FileHandle(forReadingFrom: url),
              let fileSize = try? handle.seekToEnd() else { return .empty }
        defer { try? handle.close() }

        let tailSize = min(Int(fileSize), 65_557)
        try? handle.seek(toOffset: fileSize - UInt64(tailSize))
        let tail = (try? handle.read(upToCount: tailSize)) ?? Data()
        guard let eocd = lastSignature([0x50, 0x4B, 0x05, 0x06], in: tail),
              eocd + 22 <= tail.count else {
            return InspectionReport(
                items: [.init("ZIP structure", "Central directory not found or ZIP64-only", category: .structure)],
                findings: []
            )
        }

        let declaredEntries = Int(little16(tail, eocd + 10))
        let directorySize = UInt64(little32(tail, eocd + 12))
        let directoryOffset = UInt64(little32(tail, eocd + 16))
        let readSize = Int(min(directorySize, UInt64(archiveDirectoryLimit)))
        guard directoryOffset < fileSize else { return .empty }
        try? handle.seek(toOffset: directoryOffset)
        let directory = (try? handle.read(upToCount: readSize)) ?? Data()

        var offset = 0
        var names: [String] = []
        var encryptedCount = 0
        var unsafePaths: [String] = []
        var hiddenCount = 0
        var executableCount = 0
        var symbolicLinkCount = 0
        var compressed: UInt64 = 0
        var uncompressed: UInt64 = 0
        var methods = Set<String>()
        var timestamps: [Date] = []
        var entryDetails: [String] = []

        while offset + 46 <= directory.count,
              little32(directory, offset) == 0x02014B50,
              names.count < 10_000 {
            let flags = little16(directory, offset + 8)
            let method = little16(directory, offset + 10)
            let modifiedTime = little16(directory, offset + 12)
            let modifiedDate = little16(directory, offset + 14)
            let crc = little32(directory, offset + 16)
            let compressedSize = UInt64(little32(directory, offset + 20))
            let uncompressedSize = UInt64(little32(directory, offset + 24))
            let nameLength = Int(little16(directory, offset + 28))
            let extraLength = Int(little16(directory, offset + 30))
            let commentLength = Int(little16(directory, offset + 32))
            let externalAttributes = little32(directory, offset + 38)
            let end = offset + 46 + nameLength
            guard end <= directory.count else { break }
            let nameData = directory[(offset + 46)..<end]
            let name = String(data: nameData, encoding: .utf8)
                ?? String(data: nameData, encoding: .isoLatin1)
                ?? "<unreadable name>"

            names.append(name)
            compressed += compressedSize
            uncompressed += uncompressedSize
            if flags & 0x0001 != 0 { encryptedCount += 1 }
            if isUnsafeArchivePath(name) { unsafePaths.append(name) }
            if name.split(separator: "/").contains(where: { $0.hasPrefix(".") }) { hiddenCount += 1 }
            let unixMode = externalAttributes >> 16
            if unixMode & 0o111 != 0 { executableCount += 1 }
            if unixMode & 0o170000 == 0o120000 { symbolicLinkCount += 1 }
            let methodName = zipMethodName(method)
            methods.insert(methodName)
            if let date = zipDate(date: modifiedDate, time: modifiedTime) { timestamps.append(date) }
            if entryDetails.count < 100 {
                entryDetails.append(
                    "\(name)  •  \(Int64(clamping: uncompressedSize).traceFileSize) → \(Int64(clamping: compressedSize).traceFileSize)" +
                    "  •  \(methodName)  •  CRC \(String(format: "%08X", crc))"
                )
            }
            offset = end + extraLength + commentLength
        }

        let ratio = compressed > 0 ? Double(uncompressed) / Double(compressed) : 0
        var items: [MetadataItem] = [
            .init("Archive handling", "Central directory read only — no entries extracted", category: .structure),
            .init("Declared entries", String(declaredEntries), category: .structure),
            .init("Entries inventoried", String(names.count), category: .structure),
            .init("Compressed payload", Int64(clamping: compressed).traceFileSize, category: .structure),
            .init("Declared expanded size", Int64(clamping: uncompressed).traceFileSize, category: .structure),
            .init("Compression ratio", String(format: "%.1f×", ratio), category: .structure),
            .init("Encrypted entries", String(encryptedCount), category: .structure),
            .init("Hidden paths", String(hiddenCount), category: .structure),
            .init("Executable entries", String(executableCount), category: .structure),
            .init("Symbolic links", String(symbolicLinkCount), category: .structure),
            .init("Compression methods", methods.sorted().joined(separator: ", "), category: .structure)
        ]
        if let oldest = timestamps.min(), let newest = timestamps.max() {
            items.append(.init(
                "Entry modification range",
                "\(oldest.formatted(date: .abbreviated, time: .standard)) — \(newest.formatted(date: .abbreviated, time: .standard))",
                category: .structure
            ))
        }
        if !entryDetails.isEmpty {
            items.append(.init("Entry inventory (first \(entryDetails.count))", entryDetails.joined(separator: "\n"), category: .structure))
        }
        if directorySize > UInt64(archiveDirectoryLimit) {
            items.append(.init("Inventory limit", "Central directory capped at \(Int64(archiveDirectoryLimit).traceFileSize)", category: .structure))
        }

        var findings: [PrivacyFinding] = []
        if encryptedCount > 0 {
            findings.append(.init(
                title: "Encrypted archive entries",
                detail: "\(encryptedCount) entr\(encryptedCount == 1 ? "y is" : "ies are") encrypted and could not be inspected.",
                severity: .medium,
                icon: "lock.doc.fill"
            ))
        }
        if !unsafePaths.isEmpty {
            items.append(.init("Unsafe entry paths", unsafePaths.prefix(25).joined(separator: "\n"), category: .structure))
            findings.append(.init(
                title: "Unsafe archive paths",
                detail: "Absolute or parent-directory paths were found. Trace did not extract them.",
                severity: .high,
                icon: "exclamationmark.folder.fill"
            ))
        }
        if executableCount > 0 || symbolicLinkCount > 0 {
            findings.append(.init(
                title: "Active archive entries",
                detail: "The directory declares \(executableCount) executable item(s) and \(symbolicLinkCount) symbolic link(s). Nothing was extracted or run.",
                severity: .medium,
                icon: "terminal.fill"
            ))
        }
        if ratio > 100 || uncompressed > 10_000_000_000 {
            findings.append(.init(
                title: "Potential archive expansion risk",
                detail: "The declared expanded size or compression ratio is unusually large. Nothing was decompressed.",
                severity: .high,
                icon: "archivebox.fill"
            ))
        }
        return InspectionReport(items: items, findings: findings)
    }

    private func inspectTAR(at url: URL) -> InspectionReport {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return .empty }
        defer { try? handle.close() }

        var names: [String] = []
        var unsafe: [String] = []
        var declaredBytes: UInt64 = 0
        var truncated = false

        for _ in 0..<10_000 {
            guard let header = try? handle.read(upToCount: 512),
                  header.count == 512 else { break }
            if header.allSatisfy({ $0 == 0 }) { break }

            let name = tarString(header, range: 0..<100)
            let prefix = tarString(header, range: 345..<500)
            let path = prefix.isEmpty ? name : "\(prefix)/\(name)"
            guard !path.isEmpty else { break }
            let sizeText = tarString(header, range: 124..<136)
            let size = UInt64(sizeText.trimmingCharacters(in: .whitespacesAndNewlines), radix: 8) ?? 0
            names.append(path)
            declaredBytes += size
            if isUnsafeArchivePath(path) { unsafe.append(path) }

            let padded = ((size + 511) / 512) * 512
            let current = (try? handle.offset()) ?? 0
            try? handle.seek(toOffset: current + padded)
        }
        if names.count == 10_000 { truncated = true }

        var items: [MetadataItem] = [
            .init("Archive handling", "TAR headers read only — no entries extracted", category: .structure),
            .init("Entries inventoried", String(names.count), category: .structure),
            .init("Declared payload size", Int64(clamping: declaredBytes).traceFileSize, category: .structure)
        ]
        if !names.isEmpty {
            let sample = names.prefix(100)
            items.append(.init("Entry names (first \(sample.count))", sample.joined(separator: "\n"), category: .structure))
        }
        if truncated {
            items.append(.init("Inventory limit", "Stopped after 10,000 entries", category: .structure))
        }
        var findings: [PrivacyFinding] = []
        if !unsafe.isEmpty {
            items.append(.init("Unsafe entry paths", unsafe.prefix(25).joined(separator: "\n"), category: .structure))
            findings.append(.init(
                title: "Unsafe archive paths",
                detail: "Absolute or parent-directory paths were found. Trace did not extract them.",
                severity: .high,
                icon: "exclamationmark.folder.fill"
            ))
        }
        return InspectionReport(items: items, findings: findings)
    }

    // MARK: - Static code-signing inspection

    private func inspectCodeSigning(at url: URL) -> InspectionReport {
        var code: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(), &code)
        guard createStatus == errSecSuccess, let code else {
            return InspectionReport(
                items: [.init("Code signature", "Not present or unreadable", category: .integrity)],
                findings: [
                    .init(
                        title: "Unsigned executable content",
                        detail: "No readable macOS code signature was found. The file was not launched.",
                        severity: .medium,
                        icon: "signature"
                    )
                ]
            )
        }

        let validity = SecStaticCodeCheckValidity(code, SecCSFlags(), nil)
        var items = [
            MetadataItem(
                "Code signature validity",
                validity == errSecSuccess ? "Valid" : "Invalid (status \(validity))",
                category: .integrity
            )
        ]
        var information: CFDictionary?
        if SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
           let dictionary = information as? [String: Any] {
            if let identifier = dictionary[kSecCodeInfoIdentifier as String] {
                items.append(.init("Signing identifier", String(describing: identifier), category: .integrity))
            }
            if let team = dictionary[kSecCodeInfoTeamIdentifier as String] {
                items.append(.init("Signing team", String(describing: team), category: .integrity))
            }
            if let format = dictionary[kSecCodeInfoFormat as String] {
                items.append(.init("Signing format", String(describing: format), category: .integrity))
            }
            if let entitlements = dictionary[kSecCodeInfoEntitlementsDict as String] as? [String: Any], !entitlements.isEmpty {
                items.append(.init(
                    "Signed entitlements",
                    entitlements.keys.sorted().joined(separator: "\n"),
                    category: .integrity
                ))
            }
        }
        let findings: [PrivacyFinding] = validity == errSecSuccess ? [] : [
            .init(
                title: "Invalid executable signature",
                detail: "The static code signature did not validate. Trace did not launch the file.",
                severity: .high,
                icon: "xmark.seal.fill"
            )
        ]
        return InspectionReport(items: items, findings: findings)
    }

    // MARK: - Helpers

    private func detectedSignature(
        _ data: Data,
        lastBytes: Data,
        fileExtension: String,
        fileSize: UInt64
    ) -> FileSignature {
        let bytes = [UInt8](data.prefix(16))
        if bytes.starts(with: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) { return .init(name: "PNG image", extensions: ["png"], executable: false) }
        if bytes.starts(with: [0xFF, 0xD8, 0xFF]) { return .init(name: "JPEG image", extensions: ["jpg", "jpeg"], executable: false) }
        if bytes.starts(with: Array("GIF87a".utf8)) || bytes.starts(with: Array("GIF89a".utf8)) { return .init(name: "GIF image", extensions: ["gif"], executable: false) }
        if bytes.starts(with: [0x49, 0x49, 0x2A, 0x00]) || bytes.starts(with: [0x4D, 0x4D, 0x00, 0x2A]) { return .init(name: "TIFF image", extensions: ["tif", "tiff"], executable: false) }
        if bytes.starts(with: [0x42, 0x4D]) { return .init(name: "BMP image", extensions: ["bmp"], executable: false) }
        if bytes.starts(with: Array("%PDF-".utf8)) { return .init(name: "PDF document", extensions: ["pdf"], executable: false) }
        if bytes.starts(with: [0x50, 0x4B, 0x03, 0x04]) || bytes.starts(with: [0x50, 0x4B, 0x05, 0x06]) { return .init(name: "ZIP container", extensions: ["zip", "docx", "xlsx", "pptx", "epub", "jar"], executable: false) }
        if bytes.starts(with: [0x1F, 0x8B]) { return .init(name: "GZIP stream", extensions: ["gz", "gzip", "tgz"], executable: false) }
        if bytes.starts(with: [0x42, 0x5A, 0x68]) { return .init(name: "BZIP2 stream", extensions: ["bz2"], executable: false) }
        if bytes.starts(with: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) { return .init(name: "7-Zip archive", extensions: ["7z"], executable: false) }
        if bytes.starts(with: Array("Rar!\u{1A}\u{07}".utf8)) { return .init(name: "RAR archive", extensions: ["rar"], executable: false) }
        if bytes.starts(with: Array("OggS".utf8)) { return .init(name: "Ogg container", extensions: ["ogg", "oga", "ogv", "opus"], executable: false) }
        if bytes.starts(with: Array("fLaC".utf8)) { return .init(name: "FLAC audio", extensions: ["flac"], executable: false) }
        if bytes.starts(with: Array("ID3".utf8)) { return .init(name: "MP3 audio", extensions: ["mp3"], executable: false) }
        if bytes.count >= 12,
           Array(bytes[0..<4]) == Array("RIFF".utf8),
           Array(bytes[8..<12]) == Array("WAVE".utf8) {
            return .init(name: "WAVE audio", extensions: ["wav"], executable: false)
        }
        if bytes.count >= 12,
           Array(bytes[0..<4]) == Array("RIFF".utf8),
           Array(bytes[8..<12]) == Array("AVI ".utf8) {
            return .init(name: "AVI video", extensions: ["avi"], executable: false)
        }
        if bytes.count >= 12,
           Array(bytes[0..<4]) == Array("RIFF".utf8),
           Array(bytes[8..<12]) == Array("WEBP".utf8) {
            return .init(name: "WebP image", extensions: ["webp"], executable: false)
        }
        if bytes.count >= 12, Array(bytes[4..<8]) == Array("ftyp".utf8) {
            return .init(name: "ISO base media container", extensions: ["mp4", "m4v", "mov", "heic", "heif", "avif"], executable: false)
        }
        if bytes.starts(with: [0x7F, 0x45, 0x4C, 0x46]) { return .init(name: "ELF executable", extensions: [], executable: true) }
        if bytes.starts(with: [0x4D, 0x5A]) { return .init(name: "Windows PE executable", extensions: ["exe", "dll"], executable: true) }
        if bytes.starts(with: [0x23, 0x21]) { return .init(name: "Executable script", extensions: ["sh", "zsh", "bash", "py", "rb", "pl"], executable: true) }
        if bytes.starts(with: Array("SQLite format 3\u{00}".utf8)) { return .init(name: "SQLite database", extensions: ["sqlite", "sqlite3", "db"], executable: false) }
        if lastBytes.starts(with: Array("koly".utf8)) {
            return .init(name: "Apple disk image (UDIF)", extensions: ["dmg"], executable: false)
        }
        if data.count >= 262, String(data: data[257..<262], encoding: .ascii) == "ustar" {
            return .init(name: "TAR archive", extensions: ["tar"], executable: false)
        }
        if fileExtension == "stl" {
            if String(data: data.prefix(5), encoding: .ascii)?.lowercased() == "solid" {
                return .init(name: "ASCII STL 3D model", extensions: ["stl"], executable: false)
            }
            if data.count >= 84 {
                let facets = UInt64(little32(data, 80))
                if facets <= (UInt64.max - 84) / 50, 84 + facets * 50 == fileSize {
                    return .init(name: "Binary STL 3D model", extensions: ["stl"], executable: false)
                }
            }
        }
        if fileExtension == "gcode",
           let header = String(data: data, encoding: .utf8),
           header.contains("G0") || header.contains("G1") || header.contains("HEADER_BLOCK") {
            return .init(name: "G-code toolpath", extensions: ["gcode"], executable: false)
        }
        if bytes.count >= 4 {
            let magic = big32(Data(bytes), 0)
            if [0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE, 0xCAFEBABE, 0xBEBAFECA].contains(magic) {
                return .init(name: "Mach-O executable", extensions: ["app", "dylib", "bundle"], executable: true)
            }
        }
        return .unknown
    }

    private func signatureMatchesExtension(_ signature: FileSignature, extension ext: String) -> Bool? {
        guard signature.name != FileSignature.unknown.name, !ext.isEmpty, !signature.extensions.isEmpty else { return nil }
        let formatSpecificExtensions: Set<String> = [
            "png", "jpg", "jpeg", "gif", "tif", "tiff", "bmp", "pdf",
            "zip", "docx", "xlsx", "pptx", "epub", "jar", "gz", "gzip", "tgz",
            "bz2", "7z", "rar", "ogg", "oga", "ogv", "opus", "flac", "mp3",
            "wav", "avi", "webp", "mp4", "m4v", "mov", "heic", "heif", "avif",
            "exe", "dll", "sh", "zsh", "bash", "py", "rb", "pl",
            "sqlite", "sqlite3", "db", "tar", "app", "dylib", "bundle",
            "dmg", "stl", "gcode"
        ]
        guard formatSpecificExtensions.contains(ext) else { return nil }
        return signature.extensions.contains(ext)
    }

    private func isExecutableSignature(_ signature: FileSignature) -> Bool { signature.executable }

    private func normallyHighEntropy(_ signature: FileSignature) -> Bool {
        let names = [
            "PNG image", "JPEG image", "GIF image", "WebP image", "HEIC image",
            "ZIP container", "GZIP stream", "BZIP2 stream", "7-Zip archive",
            "RAR archive", "Ogg container", "FLAC audio", "MP3 audio",
            "ISO base media container", "Apple disk image (UDIF)", "PDF document"
        ]
        return names.contains(signature.name)
    }

    private func hasExecutePermission(_ url: URL) -> Bool {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              let permissions = attributes[.posixPermissions] as? NSNumber else { return false }
        return permissions.intValue & 0o111 != 0
    }

    private func shannonEntropy(frequencies: [UInt64], count: UInt64) -> Double {
        guard count > 0 else { return 0 }
        return frequencies.reduce(0) { result, frequency in
            guard frequency > 0 else { return result }
            let probability = Double(frequency) / Double(count)
            return result - probability * log2(probability)
        }
    }

    private func hex<D: Sequence>(_ digest: D) -> String where D.Element == UInt8 {
        digest.map { String(format: "%02x", $0) }.joined()
    }

    private func matches(_ pattern: String, in text: String) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return [] }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        var seen = Set<String>()
        var result: [String] = []
        for match in regex.matches(in: text, range: range) {
            guard let swiftRange = Range(match.range, in: text) else { continue }
            let value = String(text[swiftRange])
            let key = value.lowercased()
            if seen.insert(key).inserted {
                result.append(value)
                if result.count == 25 { break }
            }
        }
        return result
    }

    private func firstCapture(_ pattern: String, in text: String) -> String? {
        guard let regex = try? NSRegularExpression(pattern: pattern),
              let match = regex.firstMatch(
                in: text,
                range: NSRange(text.startIndex..<text.endIndex, in: text)
              ),
              match.numberOfRanges > 1,
              let range = Range(match.range(at: 1), in: text) else { return nil }
        return String(text[range])
    }

    private func isImage(_ url: URL) -> Bool {
        ["jpg", "jpeg", "png", "gif", "tif", "tiff", "heic", "heif", "webp"].contains(url.pathExtension.lowercased())
    }

    private func isTextualPrivacyTarget(_ url: URL) -> Bool {
        [
            "txt", "text", "log", "md", "markdown", "rtf", "csv", "json", "xml",
            "html", "htm", "svg", "swift", "c", "h", "m", "mm", "cpp", "hpp",
            "js", "ts", "py", "rb", "sh", "zsh", "yaml", "yml", "toml",
            "gcode", "ini", "cfg", "conf", "env", "pdf"
        ].contains(url.pathExtension.lowercased())
    }

    private func flatten(_ value: Any, prefix: String, into result: inout [(String, String)]) {
        guard result.count < 500 else { return }
        if let dictionary = value as? [AnyHashable: Any] {
            for key in dictionary.keys.sorted(by: { String(describing: $0) < String(describing: $1) }) {
                guard let child = dictionary[key] else { continue }
                let rawName = String(describing: key)
                    .replacingOccurrences(of: "{", with: "")
                    .replacingOccurrences(of: "}", with: "")
                let name = readableMetadataKey(rawName, parent: prefix)
                flatten(child, prefix: prefix.isEmpty ? name : "\(prefix) › \(name)", into: &result)
            }
        } else if let array = value as? [Any] {
            let display = array.map { String(describing: $0) }.joined(separator: ", ")
            result.append((prefix, truncated(display)))
        } else if !(value is Data) {
            result.append((prefix, truncated(String(describing: value))))
        }
    }

    private func truncated(_ value: String, limit: Int = 1_000) -> String {
        value.count <= limit ? value : String(value.prefix(limit)) + "…"
    }

    private func isSensitiveMetadataKey(_ key: String) -> Bool {
        let normalized = key.lowercased()
        return [
            "author", "artist", "creator", "owner", "copyright", "gps", "location",
            "latitude", "longitude", "serial", "camera", "lens", "person", "face",
            "comment", "software", "city", "country", "province", "email",
            "identifier", "hostcomputer", "host computer"
        ].contains { normalized.contains($0) }
    }

    private func readableMetadataKey(_ key: String, parent: String) -> String {
        guard parent.contains("MakerApple") else { return key }
        let appleKeys: [String: String] = [
            "3": "Runtime",
            "8": "Acceleration vector",
            "23": "Live Photo video index",
            "32": "Media group identifier",
            "33": "HDR headroom",
            "39": "Signal-to-noise ratio",
            "43": "Photo identifier",
            "45": "Color temperature",
            "46": "Camera type",
            "47": "Focus position",
            "48": "HDR gain",
            "61": "AF confidence"
        ]
        return appleKeys[key] ?? key
    }

    private func rawPDFMarkers(at url: URL) -> [String] {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return [] }
        defer { try? handle.close() }
        let data = (try? handle.read(upToCount: 16 * 1_024 * 1_024)) ?? Data()
        let text = String(decoding: data, as: UTF8.self)
        let markers: [(String, String)] = [
            ("/JavaScript", "JavaScript action"),
            ("/JS", "JavaScript shorthand"),
            ("/EmbeddedFile", "Embedded file"),
            ("/OpenAction", "Automatic open action"),
            ("/AcroForm", "Interactive form"),
            ("/Launch", "Launch action")
        ]
        return markers.compactMap { text.contains($0.0) ? $0.1 : nil }
    }

    private func isUnsafeArchivePath(_ path: String) -> Bool {
        path.hasPrefix("/") || path.hasPrefix("\\") ||
            path.split(whereSeparator: { $0 == "/" || $0 == "\\" }).contains("..") ||
            path.range(of: #"^[A-Za-z]:[\\/]"#, options: .regularExpression) != nil
    }

    private func zipMethodName(_ method: UInt16) -> String {
        switch method {
        case 0: "Stored"
        case 8: "Deflate"
        case 9: "Deflate64"
        case 12: "BZIP2"
        case 14: "LZMA"
        case 93: "Zstandard"
        case 95: "XZ"
        case 99: "AES wrapper"
        default: "Method \(method)"
        }
    }

    private func zipDate(date: UInt16, time: UInt16) -> Date? {
        guard date != 0 else { return nil }
        var components = DateComponents()
        components.year = 1980 + Int((date >> 9) & 0x7F)
        components.month = Int((date >> 5) & 0x0F)
        components.day = Int(date & 0x1F)
        components.hour = Int((time >> 11) & 0x1F)
        components.minute = Int((time >> 5) & 0x3F)
        components.second = Int(time & 0x1F) * 2
        return Calendar.current.date(from: components)
    }

    private func tarString(_ data: Data, range: Range<Int>) -> String {
        guard range.upperBound <= data.count else { return "" }
        let bytes = data[range].prefix { $0 != 0 }
        return String(data: bytes, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }

    private func lastSignature(_ signature: [UInt8], in data: Data) -> Int? {
        guard data.count >= signature.count else { return nil }
        for index in stride(from: data.count - signature.count, through: 0, by: -1) {
            if Array(data[index..<(index + signature.count)]) == signature { return index }
        }
        return nil
    }

    private func little16(_ data: Data, _ offset: Int) -> UInt16 {
        guard offset + 2 <= data.count else { return 0 }
        return UInt16(data[offset]) | (UInt16(data[offset + 1]) << 8)
    }

    private func little32(_ data: Data, _ offset: Int) -> UInt32 {
        guard offset + 4 <= data.count else { return 0 }
        return UInt32(data[offset]) |
            (UInt32(data[offset + 1]) << 8) |
            (UInt32(data[offset + 2]) << 16) |
            (UInt32(data[offset + 3]) << 24)
    }

    private func big32(_ data: Data, _ offset: Int) -> UInt32 {
        guard offset + 4 <= data.count else { return 0 }
        return (UInt32(data[offset]) << 24) |
            (UInt32(data[offset + 1]) << 16) |
            (UInt32(data[offset + 2]) << 8) |
            UInt32(data[offset + 3])
    }

    private func big64(_ data: Data, _ offset: Int) -> UInt64 {
        guard offset + 8 <= data.count else { return 0 }
        return (UInt64(big32(data, offset)) << 32) | UInt64(big32(data, offset + 4))
    }

    private func checksumName(_ type: UInt32) -> String {
        switch type {
        case 0: "None"
        case 1: "CRC-32"
        case 2: "CRC-32"
        case 3: "CRC-32"
        case 4: "CRC-32"
        case 5: "CRC-32"
        case 6: "CRC-32"
        default: "Type \(type)"
        }
    }

    private func deduplicated(_ items: [MetadataItem]) -> [MetadataItem] {
        var seen = Set<String>()
        return items.filter { seen.insert("\($0.category.rawValue)|\($0.label)|\($0.value)").inserted }
    }

    private func deduplicated(_ findings: [PrivacyFinding]) -> [PrivacyFinding] {
        var seen = Set<String>()
        return findings.filter { seen.insert("\($0.title)|\($0.detail)").inserted }
    }
}

private struct IntegrityReport {
    let items: [MetadataItem]
    let findings: [PrivacyFinding]
    let isExecutable: Bool
}

private struct InspectionReport {
    let items: [MetadataItem]
    let findings: [PrivacyFinding]

    static let empty = InspectionReport(items: [], findings: [])
}

private struct FileSignature {
    let name: String
    let extensions: Set<String>
    let executable: Bool

    static let unknown = FileSignature(name: "Unknown or headerless data", extensions: [], executable: false)
}
