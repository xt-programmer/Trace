import SwiftUI
import UniformTypeIdentifiers

struct MainView: View {
    @Environment(ScanStore.self) private var store

    var body: some View {
        @Bindable var store = store
        ZStack {
            TraceTheme.ink.ignoresSafeArea()
            VStack(spacing: 0) {
                TopBar()
                Divider().overlay(TraceTheme.divider)
                content
            }
        }
        .tint(.accentColor)
        .onDrop(of: [.fileURL], isTargeted: $store.isDropTargeted) { providers in
            guard let provider = providers.first else { return false }
            _ = provider.loadObject(ofClass: URL.self) { url, _ in
                guard let url else { return }
                Task { @MainActor in store.inspect(url) }
            }
            return true
        }
    }

    @ViewBuilder
    private var content: some View {
        switch store.phase {
        case .idle:
            EmptyStateView()
        case .scanning(let url):
            ScanningView(fileName: url.lastPathComponent)
        case .result:
            if let result = store.result {
                ResultView(result: result)
            } else {
                EmptyStateView()
            }
        case .failed(let message):
            ErrorView(message: message)
        }
    }
}

private struct TopBar: View {
    @Environment(ScanStore.self) private var store

    var body: some View {
        @Bindable var store = store
        HStack(spacing: 14) {
            HStack(spacing: 10) {
                ZStack {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(TraceTheme.mint)
                        .frame(width: 29, height: 29)
                    Image(systemName: "scope")
                        .font(.system(size: 15, weight: .bold))
                        .foregroundStyle(.white)
                }
                Text("TRACE")
                    .font(.system(size: 14, weight: .black, design: .rounded))
                    .tracking(2.2)
            }

            Picker("Scan depth", selection: Binding(
                get: { store.mode },
                set: { store.setMode($0) }
            )) {
                ForEach(ScanMode.allCases) { mode in
                    Text(mode.rawValue).tag(mode)
                }
            }
            .labelsHidden()
            .pickerStyle(.segmented)
            .frame(width: 176)

            Spacer()

            Button {
                store.chooseFile()
            } label: {
                Label("Choose file", systemImage: "plus")
            }
            .buttonStyle(.bordered)
            .controlSize(.small)
        }
        .padding(.horizontal, 18)
        .frame(height: 49)
        .background(.bar)
    }
}

private struct SidebarView: View {
    @Environment(ScanStore.self) private var store

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Color.clear.frame(height: 52)

            Label("Workspace", systemImage: "square.grid.2x2.fill")
                .font(.system(size: 12, weight: .bold))
                .foregroundStyle(TraceTheme.secondaryText)
                .textCase(.uppercase)
                .tracking(1)
                .padding(.horizontal, 18)
                .padding(.bottom, 12)

            SidebarButton(title: "New inspection", icon: "viewfinder", isSelected: store.result == nil) {
                store.reset()
            }

            if let result = store.result {
                SidebarButton(title: result.name, icon: result.typeIcon, isSelected: true) {}
                    .lineLimit(1)
            }

            HStack {
                Text("Recent")
                    .font(.system(size: 11, weight: .bold))
                    .foregroundStyle(TraceTheme.secondaryText)
                    .textCase(.uppercase)
                    .tracking(1.1)
                Spacer()
                Text("\(store.recents.count)")
                    .font(.caption2.monospacedDigit())
                    .foregroundStyle(TraceTheme.secondaryText)
            }
            .padding(.horizontal, 18)
            .padding(.top, 28)
            .padding(.bottom, 10)

            if store.recents.isEmpty {
                Text("Files inspected in this session will appear here.")
                    .font(.caption)
                    .foregroundStyle(TraceTheme.secondaryText)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 18)
            } else {
                ForEach(store.recents) { recent in
                    Button {
                        store.inspect(recent.url)
                    } label: {
                        HStack(spacing: 10) {
                            Image(systemName: recent.icon)
                                .foregroundStyle(recent.severity.color)
                                .frame(width: 18)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(recent.name)
                                    .lineLimit(1)
                                    .font(.caption.weight(.medium))
                                Text(recent.date, style: .relative)
                                    .font(.caption2)
                                    .foregroundStyle(TraceTheme.secondaryText)
                            }
                            Spacer()
                        }
                        .contentShape(Rectangle())
                        .padding(.horizontal, 18)
                        .frame(height: 44)
                    }
                    .buttonStyle(.plain)
                }
            }

            Spacer()

            VStack(alignment: .leading, spacing: 11) {
                HStack {
                    Image(systemName: "lock.shield.fill")
                        .foregroundStyle(TraceTheme.mint)
                    Text("PRIVATE BY DESIGN")
                        .font(.system(size: 10, weight: .black))
                        .tracking(1)
                }
                Text("Files are analyzed entirely on this Mac. Trace never uploads their contents.")
                    .font(.caption)
                    .foregroundStyle(TraceTheme.secondaryText)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(15)
            .background(TraceTheme.raised, in: RoundedRectangle(cornerRadius: 12))
            .overlay {
                RoundedRectangle(cornerRadius: 12)
                    .stroke(TraceTheme.mint.opacity(0.18), lineWidth: 1)
            }
            .padding(14)
        }
        .background(TraceTheme.panel)
    }
}

private struct SidebarButton: View {
    let title: String
    let icon: String
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 11) {
                Image(systemName: icon).frame(width: 18)
                Text(title).font(.callout.weight(.semibold)).lineLimit(1)
                Spacer()
            }
            .padding(.horizontal, 12)
            .frame(height: 38)
            .background(isSelected ? TraceTheme.mint.opacity(0.13) : .clear, in: RoundedRectangle(cornerRadius: 9))
            .overlay(alignment: .leading) {
                if isSelected {
                    Capsule().fill(TraceTheme.mint).frame(width: 3, height: 20).offset(x: -1)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundStyle(isSelected ? Color.primary : TraceTheme.secondaryText)
        .padding(.horizontal, 8)
    }
}

private struct EmptyStateView: View {
    @Environment(ScanStore.self) private var store

    var body: some View {
        VStack(spacing: 0) {
            Spacer(minLength: 24)

            Button {
                store.chooseFile()
            } label: {
                VStack(spacing: 15) {
                    ZStack {
                        Circle()
                            .fill(store.isDropTargeted ? TraceTheme.mint : TraceTheme.mint.opacity(0.1))
                            .frame(width: 64, height: 64)
                        Image(systemName: store.isDropTargeted ? "arrow.down.doc.fill" : "doc.text.magnifyingglass")
                            .font(.system(size: 25, weight: .semibold))
                            .foregroundStyle(store.isDropTargeted ? Color.white : TraceTheme.mint)
                    }

                    VStack(spacing: 6) {
                        Text(store.isDropTargeted ? "Drop to inspect" : "Check a file before you share it")
                            .font(.system(size: 24, weight: .bold, design: .rounded))
                        Text(store.isDropTargeted ? "Release the file here" : "Drop a file here, or click to choose one")
                            .font(.callout)
                            .foregroundStyle(TraceTheme.secondaryText)
                    }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(TraceTheme.panel, in: RoundedRectangle(cornerRadius: 18))
                .overlay {
                    RoundedRectangle(cornerRadius: 18)
                        .stroke(
                            store.isDropTargeted ? TraceTheme.mint : TraceTheme.divider,
                            style: StrokeStyle(lineWidth: store.isDropTargeted ? 2 : 1, dash: [8, 7])
                        )
                }
                .scaleEffect(store.isDropTargeted ? 1.01 : 1)
                .animation(.easeOut(duration: 0.16), value: store.isDropTargeted)
            }
            .buttonStyle(.plain)
            .frame(maxWidth: 540, maxHeight: 230)

            HStack(spacing: 7) {
                Image(systemName: store.mode == .advanced ? "checkmark.shield.fill" : "lock.shield.fill")
                    .foregroundStyle(TraceTheme.mint)
                Text(store.mode == .advanced
                     ? "Deep inspection • no execution or extraction"
                     : "Private, local, and read-only")
            }
            .font(.caption.weight(.medium))
            .foregroundStyle(TraceTheme.secondaryText)
            .padding(.top, 18)

            Text("Images, video, audio, documents, and archives")
                .font(.caption2)
                .foregroundStyle(TraceTheme.secondaryText.opacity(0.72))
                .padding(.top, 7)

            Spacer(minLength: 24)
        }
        .padding(.horizontal, 30)
    }
}

private struct ScanningView: View {
    @Environment(ScanStore.self) private var store
    let fileName: String

    var body: some View {
        VStack(spacing: 22) {
            Spacer()
            ZStack {
                Circle().stroke(TraceTheme.raised, lineWidth: 8).frame(width: 90, height: 90)
                ProgressView().controlSize(.large).tint(TraceTheme.mint)
                Circle().stroke(TraceTheme.mint.opacity(0.18), lineWidth: 1).frame(width: 114, height: 114)
            }
            Text("Reading the trace")
                .font(.title2.bold())
            Text(fileName)
                .font(.callout)
                .foregroundStyle(TraceTheme.secondaryText)
                .lineLimit(1)
            Text(store.mode == .advanced
                 ? "Hashing • structure • identifiers • signatures"
                 : "Filesystem • format • privacy • provenance")
                .font(.caption.weight(.medium))
                .foregroundStyle(TraceTheme.mint)
            Spacer()
        }
        .padding(40)
    }
}

private struct ErrorView: View {
    @Environment(ScanStore.self) private var store
    let message: String

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 42))
                .foregroundStyle(TraceTheme.amber)
            Text("Trace couldn’t inspect this file")
                .font(.title2.bold())
            Text(message)
                .foregroundStyle(TraceTheme.secondaryText)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 480)
            Button("Choose another file") { store.chooseFile() }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

private struct ResultView: View {
    @Environment(ScanStore.self) private var store
    let result: ScanResult

    var body: some View {
        VStack(spacing: 0) {
            ResultHeader(result: result)
            Divider().overlay(TraceTheme.divider)
            HStack(spacing: 0) {
                CategoryRail(result: result)
                    .frame(width: 210)
                Divider().overlay(TraceTheme.divider)
                ResultDetail(result: result)
            }
        }
    }
}

private struct ResultHeader: View {
    @Environment(ScanStore.self) private var store
    let result: ScanResult

    var body: some View {
        HStack(spacing: 13) {
            ZStack {
                RoundedRectangle(cornerRadius: 10)
                    .fill(TraceTheme.raised)
                    .frame(width: 44, height: 44)
                Image(systemName: result.typeIcon)
                    .font(.system(size: 19, weight: .semibold))
                    .foregroundStyle(TraceTheme.mint)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(result.name).font(.headline).lineLimit(1)
                HStack(spacing: 7) {
                    Text("\(result.contentType)  •  \(result.fileSize.traceFileSize)  •  \(result.items.count) fields  •  \(result.mode.rawValue)")
                        .foregroundStyle(TraceTheme.secondaryText)
                    if result.sensitiveCount > 0 {
                        Text("\(result.sensitiveCount) SENSITIVE")
                            .font(.system(size: 9, weight: .black))
                            .tracking(0.6)
                            .foregroundStyle(TraceTheme.coral)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 3)
                            .background(TraceTheme.coral.opacity(0.12), in: Capsule())
                            .overlay { Capsule().stroke(TraceTheme.coral.opacity(0.28)) }
                    }
                }
                .font(.caption)
                .lineLimit(1)
            }
            Spacer()
            SeverityBadge(severity: result.highestSeverity)
            Menu {
                Button("Copy text report", systemImage: "doc.on.doc") { store.copyReport() }
                Button("Reveal in Finder", systemImage: "folder") { store.revealInFinder() }
            } label: {
                Image(systemName: "ellipsis")
                    .frame(width: 28, height: 28)
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 13)
        .background(TraceTheme.panel.opacity(0.55))
    }
}

private struct SeverityBadge: View {
    let severity: FindingSeverity

    var body: some View {
        HStack(spacing: 7) {
            Circle().fill(severity.color).frame(width: 7, height: 7)
            Text(severity == .info ? "Clear basic scan" : "\(severity.title) attention")
        }
        .font(.caption.weight(.bold))
        .foregroundStyle(severity.color)
        .padding(.horizontal, 11)
        .frame(height: 28)
        .background(severity.color.opacity(0.1), in: Capsule())
        .overlay { Capsule().stroke(severity.color.opacity(0.2)) }
    }
}

private struct CategoryRail: View {
    @Environment(ScanStore.self) private var store
    let result: ScanResult

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text("INSPECTION")
                .font(.system(size: 10, weight: .black))
                .tracking(1.4)
                .foregroundStyle(TraceTheme.secondaryText)
                .padding(.horizontal, 16)
                .padding(.bottom, 8)

            ForEach(visibleCategories) { category in
                Button {
                    store.selectedCategory = category
                } label: {
                    HStack(spacing: 10) {
                        Image(systemName: category.icon)
                            .foregroundStyle(category.tint)
                            .frame(width: 18)
                        Text(category.rawValue).lineLimit(1)
                        Spacer()
                        Text(count(for: category))
                            .font(.caption2.monospacedDigit())
                            .foregroundStyle(TraceTheme.secondaryText)
                    }
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 11)
                    .frame(height: 36)
                    .background(
                        store.selectedCategory == category ? TraceTheme.raised : .clear,
                        in: RoundedRectangle(cornerRadius: 8)
                    )
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }

            Spacer()

            Button {
                store.copyReport()
            } label: {
                Label("Copy report", systemImage: "doc.on.doc")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)

            Button {
                store.reset()
            } label: {
                Label("Scan another", systemImage: "arrow.counterclockwise")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(14)
        .background(TraceTheme.panel.opacity(0.55))
    }

    private func count(for category: MetadataCategory) -> String {
        category == .privacy ? "\(result.findings.count)" : "\(result.items(in: category).count)"
    }

    private var visibleCategories: [MetadataCategory] {
        MetadataCategory.allCases.filter {
            $0 == .privacy || !result.items(in: $0).isEmpty
        }
    }
}

private struct ResultDetail: View {
    @Environment(ScanStore.self) private var store
    let result: ScanResult

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 17) {
                HStack(alignment: .firstTextBaseline) {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(store.selectedCategory.rawValue)
                            .font(.title3.bold())
                        Text(subtitle)
                            .font(.caption)
                            .foregroundStyle(TraceTheme.secondaryText)
                    }
                    Spacer()
                    Text(result.scannedAt, format: .dateTime.hour().minute().second())
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(TraceTheme.secondaryText)
                }

                if store.selectedCategory == .privacy {
                    PrivacyFindingsView(findings: result.findings)
                    SensitiveFieldsView(items: result.items.filter(\.isSensitive))
                } else {
                    MetadataTable(items: result.items(in: store.selectedCategory))
                }
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(TraceTheme.ink)
    }

    private var subtitle: String {
        switch store.selectedCategory {
        case .privacy: "Signals that matter before you publish or share"
        case .file: "Basic identity and storage properties"
        case .format: "Properties derived from the file’s contents and container"
        case .integrity: "Hashes, real file signature, and binary characteristics"
        case .system: "Local filesystem and macOS-specific information"
        case .provenance: "Clues about where the file came from"
        case .structure: "Contained entries and relationships, inspected without extraction"
        }
    }
}

private struct PrivacyFindingsView: View {
    let findings: [PrivacyFinding]

    var body: some View {
        VStack(spacing: 0) {
            ForEach(Array(findings.enumerated()), id: \.element.id) { index, finding in
                HStack(alignment: .top, spacing: 13) {
                    Image(systemName: finding.icon)
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundStyle(finding.severity.color)
                        .frame(width: 34, height: 34)
                        .background(finding.severity.color.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(finding.title).font(.callout.bold())
                            Spacer()
                            Text(finding.severity.title.uppercased())
                                .font(.system(size: 9, weight: .black))
                                .tracking(0.7)
                                .foregroundStyle(finding.severity.color)
                        }
                        Text(finding.detail)
                            .font(.caption)
                            .foregroundStyle(TraceTheme.secondaryText)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                .padding(14)
                if index < findings.count - 1 {
                    Divider().overlay(TraceTheme.divider).padding(.leading, 61)
                }
            }
        }
        .background(TraceTheme.panel, in: RoundedRectangle(cornerRadius: 12))
        .overlay { RoundedRectangle(cornerRadius: 12).stroke(TraceTheme.divider) }
    }
}

private struct SensitiveFieldsView: View {
    let items: [MetadataItem]

    var body: some View {
        if !items.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 8) {
                    Image(systemName: "eye.trianglebadge.exclamationmark.fill")
                    Text("SENSITIVE IDENTIFYING INFORMATION")
                        .tracking(1.1)
                    Text("\(items.count)")
                        .monospacedDigit()
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(TraceTheme.coral.opacity(0.12), in: Capsule())
                }
                .font(.system(size: 10, weight: .black))
                .foregroundStyle(TraceTheme.coral)
                MetadataTable(items: items)
            }
            .padding(.top, 4)
        }
    }
}

private struct MetadataTable: View {
    let items: [MetadataItem]

    var body: some View {
        if items.isEmpty {
            HStack {
                Image(systemName: "tray")
                Text("No fields found in this category.")
            }
            .font(.callout)
            .foregroundStyle(TraceTheme.secondaryText)
            .frame(maxWidth: .infinity, minHeight: 100)
            .background(TraceTheme.panel, in: RoundedRectangle(cornerRadius: 12))
        } else {
            LazyVStack(spacing: 0) {
                ForEach(Array(items.enumerated()), id: \.element.id) { index, item in
                    HStack(alignment: .top, spacing: 18) {
                        VStack(alignment: .leading, spacing: 5) {
                            HStack(spacing: 6) {
                                if item.isSensitive {
                                    Image(systemName: "eye.trianglebadge.exclamationmark.fill")
                                        .foregroundStyle(TraceTheme.coral)
                                        .font(.caption)
                                }
                                Text(item.label)
                                    .font(.caption.weight(item.isSensitive ? .bold : .semibold))
                                    .foregroundStyle(item.isSensitive ? TraceTheme.coral : TraceTheme.secondaryText)
                            }
                            if item.isSensitive {
                                Text("SENSITIVE")
                                    .font(.system(size: 8, weight: .black))
                                    .tracking(0.7)
                                    .foregroundStyle(TraceTheme.coral)
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 2)
                                    .background(TraceTheme.coral.opacity(0.12), in: Capsule())
                            }
                        }
                        .frame(width: 148, alignment: .leading)

                        VStack(alignment: .leading, spacing: 4) {
                            Text(item.value)
                                .font(.system(
                                    size: 13,
                                    weight: item.isSensitive ? .semibold : .regular
                                ))
                                .foregroundStyle(Color.primary)
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            if let explanation = item.explanation {
                                Text(explanation)
                                    .font(.caption2)
                                    .foregroundStyle(TraceTheme.coral.opacity(0.82))
                            }
                        }
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 11)
                    .background(item.isSensitive ? TraceTheme.coral.opacity(0.075) : .clear)
                    .overlay(alignment: .leading) {
                        if item.isSensitive {
                            Rectangle()
                                .fill(TraceTheme.coral)
                                .frame(width: 3)
                        }
                    }
                    if index < items.count - 1 {
                        Divider().overlay(TraceTheme.divider).padding(.leading, 176)
                    }
                }
            }
            .background(TraceTheme.panel, in: RoundedRectangle(cornerRadius: 12))
            .overlay { RoundedRectangle(cornerRadius: 12).stroke(TraceTheme.divider) }
        }
    }
}

struct SettingsView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Label("Trace Settings", systemImage: "scope")
                .font(.title2.bold())
                .foregroundStyle(TraceTheme.mint)
            Text("Basic scans run entirely on this Mac and never modify the selected file.")
                .foregroundStyle(TraceTheme.secondaryText)
            GroupBox("Scan behavior") {
                LabeledContent("Default scan", value: "Basic")
                LabeledContent("Network access", value: "Disabled")
                LabeledContent("File modification", value: "Never")
            }
            Spacer()
        }
        .padding(28)
        .background(TraceTheme.ink)
    }
}
