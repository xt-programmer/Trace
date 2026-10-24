import AVFoundation
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers
import Darwin

struct BasicScanner: Sendable {
    private let keys: Set<URLResourceKey> = [
        .nameKey, .fileSizeKey, .totalFileAllocatedSizeKey,
        .creationDateKey, .contentModificationDateKey, .contentAccessDateKey,
        .isHiddenKey, .isUserImmutableKey, .isSymbolicLinkKey,
        .fileResourceIdentifierKey, .volumeNameKey,
        .volumeLocalizedFormatDescriptionKey,
        .tagNamesKey, .isUbiquitousItemKey
    ]

    func scan(url: URL) async throws -> ScanResult {
        let clock = ContinuousClock()
        let start = clock.now
        let accessGranted = url.startAccessingSecurityScopedResource()
        defer {
            if accessGranted { url.stopAccessingSecurityScopedResource() }
        }

        let normalizedURL = url.standardizedFileURL
        let values = try normalizedURL.resourceValues(forKeys: keys)
        let attributes = try FileManager.default.attributesOfItem(atPath: normalizedURL.path)
        var info = stat()
        let statResult = lstat(normalizedURL.path, &info)
        let type = fileType(for: normalizedURL)
        let contentType = displayName(for: type, extension: normalizedURL.pathExtension)
        let size = Int64(values.fileSize ?? 0)

        var items = makeFilesystemItems(
            url: normalizedURL,
            values: values,
            attributes: attributes,
            statInfo: statResult == 0 ? info : nil
        )
        items.append(contentsOf: accessControlItems(at: normalizedURL))

        let extended = extendedAttributes(at: normalizedURL)
        items.append(contentsOf: extended.items)

        if isImage(url: normalizedURL, type: type) {
            items.append(contentsOf: imageItems(at: normalizedURL))
        } else if isMovie(url: normalizedURL, type: type) || isAudio(url: normalizedURL, type: type) {
            items.append(contentsOf: await mediaItems(
                at: normalizedURL,
                isAudioOnly: isAudio(url: normalizedURL, type: type)
            ))
        } else if isText(url: normalizedURL, type: type) {
            items.append(contentsOf: textItems(at: normalizedURL))
        }

        items.append(contentsOf: contentSignatureItems(at: normalizedURL, declaredType: type))

        let findings = makeFindings(
            items: items,
            attributes: attributes,
            extendedNames: extended.names,
            type: type
        )

        return ScanResult(
            url: normalizedURL,
            scannedAt: .now,
            contentType: contentType,
            typeIcon: icon(for: type, extension: normalizedURL.pathExtension),
            fileSize: size,
            items: items,
            findings: findings,
            elapsed: start.duration(to: clock.now),
            mode: .basic
        )
    }

    private func makeFilesystemItems(
        url: URL,
        values: URLResourceValues,
        attributes: [FileAttributeKey: Any],
        statInfo: stat?
    ) -> [MetadataItem] {
        let filenameReason = filenamePrivacyReason(url.lastPathComponent)
        var result: [MetadataItem] = [
            .init("Filename", url.lastPathComponent, category: .file,
                  sensitive: filenameReason != nil, explanation: filenameReason),
            .init("Extension", url.pathExtension.isEmpty ? "None" : url.pathExtension.lowercased(), category: .file),
            .init("Full path", url.path, category: .system),
            .init("File size", Int64(values.fileSize ?? 0).traceFileSize, category: .file),
            .init("Allocated size", Int64(values.totalFileAllocatedSize ?? 0).traceFileSize, category: .file),
            .init("Kind", displayName(for: fileType(for: url), extension: url.pathExtension), category: .format),
            .init("Type identifier", fileType(for: url).identifier, category: .format),
            .init("MIME type", fileType(for: url).preferredMIMEType ?? "Unknown", category: .format)
        ]

        appendDate(values.creationDate, label: "Created", category: .system, to: &result)
        appendDate(values.contentModificationDate, label: "Modified", category: .system, to: &result)
        appendDate(values.contentAccessDate, label: "Last accessed", category: .system, to: &result)

        if let owner = attributes[.ownerAccountName] as? String {
            result.append(.init("Owner", owner, category: .system))
        }
        if let group = attributes[.groupOwnerAccountName] as? String {
            result.append(.init("Group", group, category: .system))
        }
        if let permissions = attributes[.posixPermissions] as? NSNumber {
            result.append(.init("POSIX permissions", String(format: "%04o", permissions.intValue), category: .system))
        }
        if let fileType = attributes[.type] as? FileAttributeType {
            result.append(.init("Filesystem object", fileType.rawValue, category: .system))
        }

        result.append(.init("Hidden", values.isHidden == true ? "Yes" : "No", category: .system))
        result.append(.init("Locked", values.isUserImmutable == true ? "Yes" : "No", category: .system))
        result.append(.init("Cloud item", values.isUbiquitousItem == true ? "Yes" : "No", category: .system))
        if values.isSymbolicLink == true,
           let destination = try? FileManager.default.destinationOfSymbolicLink(atPath: url.path) {
            result.append(.init("Symbolic link target", destination, category: .system))
        }

        if let tags = values.tagNames, !tags.isEmpty {
            result.append(.init("Finder tags", tags.joined(separator: ", "), category: .system))
        }
        if let volume = values.volumeName {
            result.append(.init("Volume", volume, category: .system))
        }
        if let format = values.volumeLocalizedFormatDescription {
            result.append(.init("Filesystem", format, category: .system))
        }
        if let identifier = values.fileResourceIdentifier {
            result.append(.init("File identifier", String(describing: identifier), category: .system))
        }

        if let statInfo {
            let changed = Date(
                timeIntervalSince1970: TimeInterval(statInfo.st_ctimespec.tv_sec)
                    + TimeInterval(statInfo.st_ctimespec.tv_nsec) / 1_000_000_000
            )
            result.append(.init("Metadata changed", Self.dateFormatter.string(from: changed), category: .system))
            result.append(.init("Inode", String(statInfo.st_ino), category: .system))
            result.append(.init("Hard-link count", String(statInfo.st_nlink), category: .system))
            let blocks = Int64(statInfo.st_blocks) * 512
            result.append(.init("Disk blocks", blocks.traceFileSize, category: .system))
            result.append(.init("Sparse file", blocks < Int64(values.fileSize ?? 0) ? "Yes" : "No", category: .system))
            let flags = statInfo.st_flags
            result.append(.init("Compressed flag", (flags & UInt32(UF_COMPRESSED)) != 0 ? "Yes" : "No", category: .system))
        }
        return result
    }

    private func accessControlItems(at url: URL) -> [MetadataItem] {
        guard let acl = acl_get_file(url.path, ACL_TYPE_EXTENDED) else {
            return [.init("Access control list", "None", category: .system)]
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var length: ssize_t = 0
        guard let text = acl_to_text(acl, &length) else {
            return [.init("Access control list", "Present", category: .system)]
        }
        defer { acl_free(text) }
        let value = String(cString: text).trimmingCharacters(in: .whitespacesAndNewlines)
        return [.init("Access control list", value.isEmpty ? "Present" : value, category: .system)]
    }

    private func imageItems(at url: URL) -> [MetadataItem] {
        guard let source = CGImageSourceCreateWithURL(url as CFURL, nil),
              let properties = CGImageSourceCopyPropertiesAtIndex(source, 0, nil) as? [CFString: Any] else {
            return []
        }
        var result: [MetadataItem] = []
        appendProperty(properties, key: kCGImagePropertyPixelWidth, label: "Width", suffix: " px", to: &result)
        appendProperty(properties, key: kCGImagePropertyPixelHeight, label: "Height", suffix: " px", to: &result)
        if let width = properties[kCGImagePropertyPixelWidth] as? NSNumber,
           let height = properties[kCGImagePropertyPixelHeight] as? NSNumber {
            result.append(.init(
                "Megapixels",
                String(format: "%.1f MP", width.doubleValue * height.doubleValue / 1_000_000),
                category: .format
            ))
        }
        appendProperty(properties, key: kCGImagePropertyColorModel, label: "Color model", to: &result)
        appendProperty(properties, key: kCGImagePropertyHasAlpha, label: "Alpha channel", to: &result)
        appendProperty(properties, key: kCGImagePropertyDPIWidth, label: "Horizontal DPI", to: &result)
        appendProperty(properties, key: kCGImagePropertyDPIHeight, label: "Vertical DPI", to: &result)
        appendProperty(properties, key: kCGImagePropertyDepth, label: "Bit depth", to: &result)
        appendProperty(properties, key: kCGImagePropertyProfileName, label: "Color profile", to: &result)
        appendProperty(properties, key: kCGImagePropertyOrientation, label: "Orientation", to: &result)

        if let exif = properties[kCGImagePropertyExifDictionary] as? [CFString: Any] {
            appendProperty(exif, key: kCGImagePropertyExifDateTimeOriginal, label: "Captured", sensitive: true, to: &result)
            appendProperty(exif, key: kCGImagePropertyExifExposureTime, label: "Exposure", suffix: " s", to: &result)
            appendProperty(exif, key: kCGImagePropertyExifFNumber, label: "Aperture", prefix: "ƒ/", to: &result)
            appendProperty(exif, key: kCGImagePropertyExifISOSpeedRatings, label: "ISO", to: &result)
            appendProperty(exif, key: kCGImagePropertyExifLensModel, label: "Lens", sensitive: true, to: &result)
            appendProperty(exif, key: kCGImagePropertyExifBodySerialNumber, label: "Camera serial number", sensitive: true, to: &result)
            appendProperty(exif, key: kCGImagePropertyExifLensSerialNumber, label: "Lens serial number", sensitive: true, to: &result)
            appendProperty(exif, key: kCGImagePropertyExifUserComment, label: "Embedded comment", sensitive: true, to: &result)
        }
        if let tiff = properties[kCGImagePropertyTIFFDictionary] as? [CFString: Any] {
            appendProperty(tiff, key: kCGImagePropertyTIFFMake, label: "Camera maker", sensitive: true, to: &result)
            appendProperty(tiff, key: kCGImagePropertyTIFFModel, label: "Camera model", sensitive: true, to: &result)
            appendProperty(tiff, key: kCGImagePropertyTIFFSoftware, label: "Editing software", sensitive: true, to: &result)
            appendProperty(tiff, key: kCGImagePropertyTIFFArtist, label: "Artist", sensitive: true, to: &result)
            appendProperty(tiff, key: kCGImagePropertyTIFFCopyright, label: "Copyright", sensitive: true, to: &result)
        }
        if let gps = properties[kCGImagePropertyGPSDictionary] as? [CFString: Any] {
            if let latitude = coordinate(gps, valueKey: kCGImagePropertyGPSLatitude, referenceKey: kCGImagePropertyGPSLatitudeRef),
               let longitude = coordinate(gps, valueKey: kCGImagePropertyGPSLongitude, referenceKey: kCGImagePropertyGPSLongitudeRef) {
                result.append(.init("GPS coordinates", "\(latitude), \(longitude)", category: .format, sensitive: true,
                                    explanation: "Precise coordinates can reveal where the content was captured."))
            }
            appendProperty(gps, key: kCGImagePropertyGPSDateStamp, label: "GPS date", sensitive: true, to: &result)
        }
        if let iptc = properties[kCGImagePropertyIPTCDictionary] as? [CFString: Any] {
            appendProperty(iptc, key: kCGImagePropertyIPTCByline, label: "Creator", sensitive: true, to: &result)
            appendProperty(iptc, key: kCGImagePropertyIPTCCity, label: "City", sensitive: true, to: &result)
            appendProperty(iptc, key: kCGImagePropertyIPTCProvinceState, label: "State / province", sensitive: true, to: &result)
            appendProperty(iptc, key: kCGImagePropertyIPTCCountryPrimaryLocationName, label: "Country", sensitive: true, to: &result)
            appendProperty(iptc, key: kCGImagePropertyIPTCObjectName, label: "Title", sensitive: true, to: &result)
        }
        return result
    }

    private func mediaItems(at url: URL, isAudioOnly: Bool) async -> [MetadataItem] {
        let asset = AVURLAsset(url: url)
        var result: [MetadataItem] = []
        do {
            let duration = try await asset.load(.duration)
            if duration.isNumeric {
                let seconds = CMTimeGetSeconds(duration)
                result.append(.init("Duration", Self.durationFormatter.string(from: seconds) ?? "\(seconds) s", category: .format))
                if seconds > 0,
                   let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize {
                    let bitrate = Double(size) * 8 / seconds
                    result.append(.init("Overall bitrate", Self.bitrateFormatter.string(from: NSNumber(value: bitrate)) ?? "\(Int(bitrate)) bit/s", category: .format))
                }
            }
            let tracks = try await asset.load(.tracks)
            let videoTracks = tracks.filter { $0.mediaType == .video }
            let audioTracks = tracks.filter { $0.mediaType == .audio }
            result.append(.init("Video tracks", String(videoTracks.count), category: .format))
            result.append(.init("Audio tracks", String(audioTracks.count), category: .format))

            if let video = videoTracks.first {
                let size = try await video.load(.naturalSize)
                let transform = try await video.load(.preferredTransform)
                let transformed = size.applying(transform)
                result.append(.init("Resolution", "\(Int(abs(transformed.width))) × \(Int(abs(transformed.height)))", category: .format))
                let rate = try await video.load(.nominalFrameRate)
                if rate > 0 {
                    result.append(.init("Frame rate", String(format: "%.2f fps", rate), category: .format))
                    let seconds = CMTimeGetSeconds(duration)
                    if seconds.isFinite, seconds > 0 {
                        result.append(.init("Estimated frame count", String(Int((seconds * Double(rate)).rounded())), category: .format))
                    }
                }
                let timeScale = try await video.load(.naturalTimeScale)
                result.append(.init("Video time scale", "\(timeScale) units/s", category: .format))
                let descriptions = try await video.load(.formatDescriptions)
                if let description = descriptions.first {
                    result.append(.init("Video codec", fourCC(CMFormatDescriptionGetMediaSubType(description)), category: .format))
                    result.append(contentsOf: videoFormatExtensionItems(description))
                }
                let bitrate = try await video.load(.estimatedDataRate)
                if bitrate > 0 {
                    result.append(.init("Video bitrate", Self.bitrateFormatter.string(from: NSNumber(value: bitrate)) ?? "\(Int(bitrate)) bit/s", category: .format))
                }
            }
            if let audio = audioTracks.first {
                let descriptions = try await audio.load(.formatDescriptions)
                if let description = descriptions.first {
                    result.append(.init("Audio codec", fourCC(CMFormatDescriptionGetMediaSubType(description)), category: .format))
                    if let basic = CMAudioFormatDescriptionGetStreamBasicDescription(description)?.pointee {
                        result.append(.init("Sample rate", "\(Int(basic.mSampleRate)) Hz", category: .format))
                        result.append(.init("Channels", String(basic.mChannelsPerFrame), category: .format))
                    }
                }
                let bitrate = try await audio.load(.estimatedDataRate)
                if bitrate > 0 {
                    result.append(.init("Audio bitrate", Self.bitrateFormatter.string(from: NSNumber(value: bitrate)) ?? "\(Int(bitrate)) bit/s", category: .format))
                }
            }

            let metadata = try await asset.load(.commonMetadata)
            for item in metadata {
                guard let key = item.commonKey,
                      [.commonKeyTitle, .commonKeyArtist, .commonKeyAlbumName, .commonKeyCreator, .commonKeyCopyrights, .commonKeyCreationDate].contains(key),
                      let value = try? await item.load(.stringValue),
                      !value.isEmpty else { continue }
                let label = key.rawValue
                    .replacingOccurrences(of: "commonKey", with: "")
                    .replacingOccurrences(of: "([a-z])([A-Z])", with: "$1 $2", options: .regularExpression)
                    .capitalized
                result.append(.init(label, value, category: .format, sensitive: true))
            }
            let formats = try await asset.load(.availableMetadataFormats)
            for format in formats {
                let formatMetadata = try await asset.loadMetadata(for: format)
                for item in formatMetadata {
                    let identifier = item.identifier?.rawValue.lowercased() ?? ""
                    let interesting = ["creationdate", "software", "make", "model", "location", "encodedby"]
                    guard interesting.contains(where: identifier.contains) else { continue }
                    let label: String
                    if identifier.contains("creationdate") {
                        label = "Container creation date"
                    } else if identifier.contains("location") {
                        label = "Container location"
                    } else if identifier.contains("software") || identifier.contains("encodedby") {
                        label = "Encoder application"
                    } else if identifier.contains("model") {
                        label = "Recording device model"
                    } else {
                        label = "Recording device maker"
                    }
                    if let value = try? await item.load(.stringValue), !value.isEmpty {
                        result.append(.init(label, value, category: .format,
                                            sensitive: label.contains("location") || label.contains("device")))
                    } else if let date = try? await item.load(.dateValue) {
                        result.append(.init(label, Self.dateFormatter.string(from: date), category: .format,
                                            sensitive: true))
                    }
                }
            }
        } catch {
            result.append(.init("Media inspection", "Some stream properties were unavailable", category: .format))
        }
        if isAudioOnly {
            result.removeAll { $0.label == "Video tracks" }
        }
        return result
    }

    private func videoFormatExtensionItems(_ description: CMFormatDescription) -> [MetadataItem] {
        guard let extensions = CMFormatDescriptionGetExtensions(description) as? [String: Any] else { return [] }
        let wanted = [
            "CVImageBufferColorPrimaries", "CVImageBufferTransferFunction",
            "CVImageBufferYCbCrMatrix", "CVImageBufferChromaLocationTopField",
            "CVImageBufferChromaLocationBottomField", "FullRangeVideo",
            "BitsPerComponent", "Depth"
        ]
        var result: [MetadataItem] = wanted.compactMap { key -> MetadataItem? in
            guard let value = extensions[key] else { return nil }
            let label = key
                .replacingOccurrences(of: "CVImageBuffer", with: "")
                .replacingOccurrences(of: "([a-z])([A-Z])", with: "$1 $2", options: .regularExpression)
            return MetadataItem(label, String(describing: value), category: .format)
        }
        if let atoms = extensions["SampleDescriptionExtensionAtoms"] as? [String: Data],
           let avcConfiguration = atoms["avcC"], avcConfiguration.count >= 4 {
            let profile = avcProfileName(avcConfiguration[1])
            let level = Double(avcConfiguration[3]) / 10
            result.append(.init("Codec profile", profile, category: .format))
            result.append(.init("Codec level", String(format: "%.1f", level), category: .format))
        }
        return result
    }

    private func avcProfileName(_ value: UInt8) -> String {
        switch value {
        case 66: "Baseline"
        case 77: "Main"
        case 88: "Extended"
        case 100: "High"
        case 110: "High 10"
        case 122: "High 4:2:2"
        case 244: "High 4:4:4"
        default: "Profile \(value)"
        }
    }

    private func textItems(at url: URL) -> [MetadataItem] {
        // Bound the read itself, rather than mapping the entire file before sampling.
        let sampleLimit = 1_000_000
        guard let handle = try? FileHandle(forReadingFrom: url) else { return [] }
        defer { try? handle.close() }
        guard let data = try? handle.read(upToCount: sampleLimit + 1) else { return [] }
        let isSampled = data.count > sampleLimit
        let prefix = Data(data.prefix(sampleLimit))
        let encoding = detectTextEncoding(prefix)
        var result = [
            MetadataItem("Text encoding", encoding.name, category: .format),
            MetadataItem("Byte-order mark", encoding.hasBOM ? "Present" : "None", category: .format)
        ]
        result.append(.init(
            "Text scan coverage",
            isSampled ? "First 1,000,000 bytes (sampled)" : "Entire file",
            category: .format
        ))
        if let text = String(data: prefix, encoding: encoding.value) {
            result.append(.init(isSampled ? "Lines (sampled)" : "Lines", String(text.split(whereSeparator: \.isNewline).count), category: .format))
            result.append(.init("Words (sampled)", String(text.split(whereSeparator: \.isWhitespace).count), category: .format))
        }
        return result
    }

    private func contentSignatureItems(at url: URL, declaredType: UTType) -> [MetadataItem] {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return [] }
        defer { try? handle.close() }
        let bytes = (try? handle.read(upToCount: 16)) ?? Data()
        let signature = bytes.prefix(8).map { String(format: "%02X", $0) }.joined(separator: " ")
        var items = [MetadataItem("Header signature", signature.isEmpty ? "Empty file" : signature, category: .format)]
        if isArchive(url: url, type: declaredType) {
            items.append(.init("Archive container", "Detected — contents not expanded in Basic scan", category: .format))
        }
        return items
    }

    private func extendedAttributes(at url: URL) -> (names: [String], items: [MetadataItem]) {
        let length = listxattr(url.path, nil, 0, XATTR_NOFOLLOW)
        guard length > 0 else {
            return ([], [.init("Extended attributes", "None", category: .system)])
        }
        var buffer = [CChar](repeating: 0, count: length)
        let result = listxattr(url.path, &buffer, buffer.count, XATTR_NOFOLLOW)
        guard result > 0 else { return ([], []) }

        let names = buffer.split(separator: 0).map { segment in
            segment.withUnsafeBufferPointer { pointer in
                String(decoding: pointer.map { UInt8(bitPattern: $0) }, as: UTF8.self)
            }
        }
        var items = [MetadataItem("Extended attributes", names.joined(separator: ", "), category: .system)]
        if names.contains("com.apple.quarantine") {
            let detail = quarantineDescription(
                readExtendedAttribute(named: "com.apple.quarantine", at: url)
            )
            items.append(.init("Quarantine", detail, category: .provenance, sensitive: true,
                               explanation: "macOS recorded this file as coming from an external source."))
        } else {
            items.append(.init("Quarantine", "Not present", category: .provenance))
        }
        if names.contains("com.apple.metadata:kMDItemWhereFroms") {
            let originData = readExtendedAttribute(named: "com.apple.metadata:kMDItemWhereFroms", at: url)
            let origins = originData.flatMap(propertyListStrings) ?? []
            let value = origins.isEmpty ? "Stored in extended attributes" : origins.joined(separator: "\n")
            items.append(.init("Download origin", value, category: .provenance, sensitive: true,
                               explanation: "The original download address may be retained by macOS."))
        }
        if names.contains("com.apple.ResourceFork") {
            items.append(.init("Resource fork", "Present", category: .system))
        }
        if names.contains("com.apple.metadata:kMDItemFinderComment"),
           let data = readExtendedAttribute(named: "com.apple.metadata:kMDItemFinderComment", at: url),
           let comments = propertyListStrings(data), !comments.isEmpty {
            items.append(.init("Finder comment", comments.joined(separator: "\n"), category: .system))
        }
        return (names, items)
    }

    private func makeFindings(
        items: [MetadataItem],
        attributes: [FileAttributeKey: Any],
        extendedNames: [String],
        type: UTType
    ) -> [PrivacyFinding] {
        var findings: [PrivacyFinding] = []
        let labels = Set(items.filter(\.isSensitive).map(\.label))

        if labels.contains("GPS coordinates") || labels.contains("City") || labels.contains("State / province") {
            findings.append(.init(
                title: "Location data is embedded",
                detail: "Publishing this file may disclose where it was created.",
                severity: .high,
                icon: "location.fill"
            ))
        }
        let deviceLabels = ["Camera maker", "Camera model", "Camera serial number", "Lens", "Lens serial number"]
        let matchedDevices = deviceLabels.filter(labels.contains)
        if !matchedDevices.isEmpty {
            findings.append(.init(
                title: "Capture device details",
                detail: "\(matchedDevices.count) device field\(matchedDevices.count == 1 ? "" : "s") can help correlate this file with other content.",
                severity: labels.contains("Camera serial number") || labels.contains("Lens serial number") ? .high : .medium,
                icon: "camera.fill"
            ))
        }
        let identityLabels = ["Artist", "Creator", "Copyright", "Title"]
        let matchedIdentity = identityLabels.filter(labels.contains)
        if !matchedIdentity.isEmpty {
            findings.append(.init(
                title: "Identity-related fields",
                detail: matchedIdentity.joined(separator: ", ") + " may reveal authorship or account information.",
                severity: .medium,
                icon: "person.crop.circle.badge.exclamationmark"
            ))
        }
        if labels.contains("Filename") {
            findings.append(.init(
                title: "Identifying filename",
                detail: "The filename contains a timestamp or stable identifier that may remain visible after upload.",
                severity: .medium,
                icon: "textformat.abc.dottedunderline"
            ))
        }
        if extendedNames.contains("com.apple.metadata:kMDItemWhereFroms") {
            findings.append(.init(
                title: "Original download source retained",
                detail: "macOS may have stored the URL this file came from.",
                severity: .medium,
                icon: "link"
            ))
        } else if extendedNames.contains("com.apple.quarantine") {
            findings.append(.init(
                title: "External origin recorded",
                detail: "A quarantine marker identifies the file as externally acquired.",
                severity: .low,
                icon: "arrow.down.circle.fill"
            ))
        }
        if let permissions = attributes[.posixPermissions] as? NSNumber,
           permissions.intValue & 0o002 != 0 {
            findings.append(.init(
                title: "World-writable permissions",
                detail: "Any local user can modify this file.",
                severity: .high,
                icon: "exclamationmark.lock.fill"
            ))
        }
        if type.conforms(to: .executable) {
            findings.append(.init(
                title: "Executable content",
                detail: "Treat the file as active code and verify its source before running it.",
                severity: .medium,
                icon: "terminal.fill"
            ))
        }
        if findings.isEmpty {
            findings.append(.init(
                title: "No obvious sensitive fields",
                detail: "The Basic scan found no high-signal privacy or security metadata.",
                severity: .info,
                icon: "checkmark.shield.fill"
            ))
        }
        return findings.sorted { $0.severity > $1.severity }
    }

    private func readExtendedAttribute(named name: String, at url: URL) -> Data? {
        let size = getxattr(url.path, name, nil, 0, 0, XATTR_NOFOLLOW)
        guard size > 0 else { return nil }
        var bytes = [UInt8](repeating: 0, count: size)
        let read = getxattr(url.path, name, &bytes, bytes.count, 0, XATTR_NOFOLLOW)
        guard read > 0 else { return nil }
        return Data(bytes.prefix(read))
    }

    private func propertyListStrings(_ data: Data) -> [String]? {
        guard let value = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) else {
            return nil
        }
        if let strings = value as? [String] { return strings }
        if let string = value as? String { return [string] }
        return nil
    }

    private func quarantineDescription(_ data: Data?) -> String {
        guard let data, let record = String(data: data, encoding: .utf8) else { return "Present" }
        let fields = record.split(separator: ";", omittingEmptySubsequences: false)
        var details: [String] = ["Present"]
        if fields.count > 2, !fields[2].isEmpty {
            details.append("source: \(fields[2])")
        }
        if fields.count > 1, let timestamp = UInt64(fields[1], radix: 16) {
            let date = Date(timeIntervalSince1970: TimeInterval(timestamp))
            details.append("recorded \(Self.dateFormatter.string(from: date))")
        }
        return details.joined(separator: " • ")
    }

    private func appendDate(
        _ date: Date?,
        label: String,
        category: MetadataCategory,
        to result: inout [MetadataItem]
    ) {
        if let date {
            result.append(.init(label, Self.dateFormatter.string(from: date), category: category))
        }
    }

    private func appendProperty(
        _ dictionary: [CFString: Any],
        key: CFString,
        label: String,
        prefix: String = "",
        suffix: String = "",
        sensitive: Bool = false,
        to result: inout [MetadataItem]
    ) {
        guard let value = dictionary[key] else { return }
        let display: String
        if let array = value as? [Any] {
            display = array.map(String.init(describing:)).joined(separator: ", ")
        } else {
            display = String(describing: value)
        }
        result.append(.init(label, prefix + display + suffix, category: .format, sensitive: sensitive))
    }

    private func coordinate(
        _ gps: [CFString: Any],
        valueKey: CFString,
        referenceKey: CFString
    ) -> String? {
        guard var value = gps[valueKey] as? Double else { return nil }
        let reference = (gps[referenceKey] as? String)?.uppercased()
        if reference == "S" || reference == "W" { value *= -1 }
        return String(format: "%.6f", value)
    }

    private func detectTextEncoding(_ data: Data) -> (value: String.Encoding, name: String, hasBOM: Bool) {
        let bytes = [UInt8](data.prefix(4))
        if bytes.starts(with: [0xEF, 0xBB, 0xBF]) { return (.utf8, "UTF-8", true) }
        if bytes.starts(with: [0xFF, 0xFE, 0x00, 0x00]) { return (.utf32LittleEndian, "UTF-32 LE", true) }
        if bytes.starts(with: [0x00, 0x00, 0xFE, 0xFF]) { return (.utf32BigEndian, "UTF-32 BE", true) }
        if bytes.starts(with: [0xFF, 0xFE]) { return (.utf16LittleEndian, "UTF-16 LE", true) }
        if bytes.starts(with: [0xFE, 0xFF]) { return (.utf16BigEndian, "UTF-16 BE", true) }
        if String(data: data, encoding: .utf8) != nil { return (.utf8, "UTF-8", false) }
        return (.isoLatin1, "ISO Latin-1 (estimated)", false)
    }

    private func icon(for type: UTType, extension ext: String = "") -> String {
        if ext.lowercased() == "stl" { return "cube.fill" }
        if ext.lowercased() == "gcode" { return "printer.filled.and.paper" }
        if ext.lowercased() == "dmg" { return "opticaldiscdrive.fill" }
        if [.jpeg, .png, .gif, .tiff, .heic, .webP, .svg].contains(type) { return "photo.fill" }
        if [.quickTimeMovie, .mpeg4Movie, .avi].contains(type) { return "film.fill" }
        if [.mp3, .mpeg4Audio, .wav, .aiff].contains(type) { return "waveform" }
        if [.zip, .gzip, .bz2].contains(type) || type.identifier == "public.tar-archive" {
            return "archivebox.fill"
        }
        if type.conforms(to: .image) { return "photo.fill" }
        if type.conforms(to: .movie) { return "film.fill" }
        if type.conforms(to: .audio) { return "waveform" }
        if type.conforms(to: .archive) { return "archivebox.fill" }
        if type.conforms(to: .pdf) { return "doc.richtext.fill" }
        if type.conforms(to: .text) { return "doc.text.fill" }
        if type.conforms(to: .executable) { return "terminal.fill" }
        return "doc.fill"
    }

    private func isImage(url: URL, type: UTType) -> Bool {
        let extensions = ["jpg", "jpeg", "png", "gif", "tif", "tiff", "heic", "heif", "webp", "svg"]
        return extensions.contains(url.pathExtension.lowercased()) || type.conforms(to: .image)
    }

    private func isMovie(url: URL, type: UTType) -> Bool {
        let extensions = ["mov", "mp4", "m4v", "avi", "mkv", "webm", "mpeg", "mpg"]
        return extensions.contains(url.pathExtension.lowercased()) || type.conforms(to: .movie)
    }

    private func isAudio(url: URL, type: UTType) -> Bool {
        let extensions = ["mp3", "m4a", "wav", "aif", "aiff", "flac", "aac", "ogg"]
        return extensions.contains(url.pathExtension.lowercased()) || type.conforms(to: .audio)
    }

    private func isText(url: URL, type: UTType) -> Bool {
        let extensions = [
            "txt", "text", "log", "md", "markdown", "rtf", "csv", "json", "xml",
            "html", "htm", "swift", "c", "h", "m", "mm", "cpp", "hpp", "js", "ts",
            "py", "rb", "sh", "zsh", "yaml", "yml", "toml", "gcode"
        ]
        return extensions.contains(url.pathExtension.lowercased()) || type.conforms(to: .text)
    }

    private func isArchive(url: URL, type: UTType) -> Bool {
        let extensions = ["zip", "gz", "gzip", "bz2", "tar", "tgz", "7z", "rar"]
        return extensions.contains(url.pathExtension.lowercased()) || type.conforms(to: .archive)
    }

    private func fileType(for url: URL) -> UTType {
        switch url.pathExtension.lowercased() {
        case "txt", "text", "log": return .plainText
        case "md", "markdown": return .plainText
        case "rtf": return .rtf
        case "csv": return .commaSeparatedText
        case "json": return .json
        case "xml": return .xml
        case "html", "htm": return .html
        case "swift": return .swiftSource
        case "c", "h", "m", "mm", "cpp", "hpp", "js", "ts", "py", "rb", "sh", "zsh", "yaml", "yml", "toml":
            return .sourceCode
        case "gcode": return .plainText
        case "jpg", "jpeg": return .jpeg
        case "png": return .png
        case "gif": return .gif
        case "tif", "tiff": return .tiff
        case "heic", "heif": return .heic
        case "webp": return .webP
        case "svg": return .svg
        case "mov": return .quickTimeMovie
        case "mp4", "m4v": return .mpeg4Movie
        case "avi": return .avi
        case "mp3": return .mp3
        case "m4a": return .mpeg4Audio
        case "wav": return .wav
        case "aif", "aiff": return .aiff
        case "pdf": return .pdf
        case "zip": return .zip
        case "gz", "gzip": return .gzip
        case "bz2": return .bz2
        case "tar": return UTType("public.tar-archive") ?? .archive
        default: return UTType(filenameExtension: url.pathExtension) ?? .data
        }
    }

    private func displayName(for type: UTType, extension ext: String = "") -> String {
        if ext.lowercased() == "gcode" { return "G-code toolpath" }
        if ext.lowercased() == "stl" { return "STL 3D model" }
        if ext.lowercased() == "dmg" { return "Apple disk image" }
        if type == .plainText { return "Plain text" }
        if type == .commaSeparatedText { return "Comma-separated values" }
        if type == .jpeg { return "JPEG image" }
        if type == .png { return "PNG image" }
        if type == .gif { return "GIF image" }
        if type == .tiff { return "TIFF image" }
        if type == .heic { return "HEIC image" }
        if type == .quickTimeMovie { return "QuickTime movie" }
        if type == .mpeg4Movie { return "MPEG-4 movie" }
        if type == .mp3 { return "MP3 audio" }
        if type == .mpeg4Audio { return "MPEG-4 audio" }
        if type == .pdf { return "PDF document" }
        if type == .zip { return "ZIP archive" }
        return type.localizedDescription ?? type.identifier
    }

    private func filenamePrivacyReason(_ filename: String) -> String? {
        let timestampPattern = #"\b(?:19|20)\d{2}[-_ ]\d{2}[-_ ]\d{2}(?:[-_ ,]\d{2}[:_]\d{2}(?::\d{2})?)?"#
        let namedDatePattern = #"(?i)\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*[ _-]+\d{1,2},?[ _-]+(?:19|20)\d{2}(?:,?[ _-]+\d{1,2}[:_]\d{2}(?:[:_]\d{2})?)?"#
        let uuidPattern = #"\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[1-5][0-9A-Fa-f]{3}-[89ABab][0-9A-Fa-f]{3}-[0-9A-Fa-f]{12}\b"#
        if filename.range(of: timestampPattern, options: .regularExpression) != nil
            || filename.range(of: namedDatePattern, options: .regularExpression) != nil {
            return "The filename contains a date or time that may disclose when the file was created."
        }
        if filename.range(of: uuidPattern, options: .regularExpression) != nil {
            return "The filename contains a stable unique identifier that can correlate copies of the file."
        }
        return nil
    }

    private func fourCC(_ code: FourCharCode) -> String {
        let bytes: [UInt8] = [
            UInt8((code >> 24) & 0xff), UInt8((code >> 16) & 0xff),
            UInt8((code >> 8) & 0xff), UInt8(code & 0xff)
        ]
        let value = String(bytes: bytes, encoding: .ascii)?.trimmingCharacters(in: .whitespacesAndNewlines)
        return value?.isEmpty == false ? value! : String(format: "0x%08X", code)
    }

    private static let dateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium
        return formatter
    }()

    private static let durationFormatter: DateComponentsFormatter = {
        let formatter = DateComponentsFormatter()
        formatter.allowedUnits = [.hour, .minute, .second]
        formatter.unitsStyle = .positional
        formatter.zeroFormattingBehavior = .pad
        return formatter
    }()

    private static let bitrateFormatter: NumberFormatter = {
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        formatter.maximumFractionDigits = 0
        formatter.positiveSuffix = " bit/s"
        return formatter
    }()
}
