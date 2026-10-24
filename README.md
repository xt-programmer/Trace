# Trace

**See what your files reveal.** Trace is a native macOS app for inspecting file metadata, provenance markers, and potential privacy concerns before sharing a file.

Choose a file or drag it into the window. **Basic** provides a quick metadata overview; **Advanced** adds hashes, embedded-identifier checks, and deeper format inspection. Processing runs locally, with no account, API key, or third-party package dependencies.

## What it inspects

| Area | Basic | Advanced adds |
| --- | --- | --- |
| Filesystem | Size, dates, ownership, permissions, ACLs, Finder tags, extended attributes, volume and file identity | Additional local provenance, including Apple Photos attributes |
| Photos | Dimensions, color profile, EXIF, TIFF, IPTC, GPS, camera and editing metadata | Image properties across frames, Content Credentials/C2PA and declared AI-generation markers |
| Video and audio | Duration, tracks, codecs, resolution, frame rate, sample rate, descriptive metadata | Bitrate, color characteristics, codec profile/level, time scale and estimated frame count |
| Text | Encoding, byte-order mark, line and sampled word counts | Embedded email addresses, IPv4 addresses, paths, URLs, invisible characters and possible credential assignments |
| Integrity | Header checks for selected formats | Whole-file SHA-256, SHA-1, MD5, byte entropy, signature and extension consistency |
| Documents | General file information | PDF metadata, page geometry, encryption, annotations, forms, embedded-file and JavaScript/action markers |
| Archives and disk images | General file information | ZIP central-directory and TAR-header inventories, unsafe-path and expansion-risk warnings, UDIF/DMG trailer information |
| Other formats | General file information | STL geometry, G-code print metadata, static code-signing and entitlement information |

Findings are grouped by severity, with a copyable text report and a **Reveal in Finder** action. Recent inspections are kept in the current app session.

## Requirements

- **macOS 14 or newer.**
- **Swift 6 or newer**, with a compatible macOS SDK.
- Xcode or Apple's command-line developer tools.

Trace uses SwiftUI, AppKit, AVFoundation, CryptoKit, Image I/O, PDFKit, Security, and Uniform Type Identifiers. It is macOS-only.

## Build and run

```sh
git clone https://github.com/xt-programmer/Trace.git
cd Trace
swift run Trace
```

To create a launchable app bundle directly with the selected Apple toolchain:

```sh
./scripts/build-app.sh
open Build/Trace.app
```

The script uses `SDKROOT` when supplied, otherwise discovers the SDK using `xcrun`, compiles for the current Mac's architecture, and applies an **ad-hoc signature**. It does not notarize the app or create an installer. No full Xcode installation is required if compatible command-line tools are installed.

## Using Trace

1. Choose **Basic** for a quick overview or **Advanced** for deeper inspection.
2. Open a local file using **Choose file**, drag and drop, or **Command–O**.
3. Review **Privacy & Security**, then inspect the relevant metadata categories.
4. Use **Copy report** to copy the findings, or **Reveal in Finder** to locate the file.

Changing the scan mode re-inspects the current file. The original file is not edited. Trace is an inspector; it does not remove metadata or sanitize files.

## Privacy and interpretation

- Inspection runs locally. The source contains no upload client or analytics integration.
- Trace does not launch the executable being inspected, run embedded scripts, mount disk images, or extract archive contents to disk.
- Possible credential-assignment values are intentionally hidden by that detector. Other metadata and embedded URLs can still contain sensitive text.
- **Copied reports may contain personal information**, including filenames, local paths, ownership, GPS coordinates, and embedded identifiers. Review reports before sharing them.
- Findings are heuristics. A clean report does not prove a file is safe to publish, and a flagged value is not necessarily a secret or a threat.
- C2PA and AI-generation checks detect declared markers. They do not validate cryptographic trust or determine whether an unmarked image was AI-generated.
- SHA-1 and MD5 are provided for legacy comparison; use SHA-256 for stronger integrity checks. A hash alone does not establish that a file is trustworthy.

## Inspection limits

Basic text inspection reads up to **1,000,000 bytes**, plus one byte to detect truncation. Large-file line counts are explicitly labeled as sampled; word counts describe the decoded sample. Counts omit empty lines and depend on the detected encoding.

Advanced identifier scanning examines up to **32 MiB**. Archive directory parsing also has a **32 MiB** limit. Hashing and byte-entropy analysis read the whole file in chunks, so Advanced mode can take longer for large files.

Format-specific metadata depends on the file and on macOS framework support. Archive inventory is not recursive malware analysis. These limits do not impose a universal memory or runtime bound on every Apple framework parser.

## Development and checks

Run the package tests:

```sh
swift test
```

A standalone smoke test can exercise the scanners if Swift Package Manager is unavailable:

```sh
mkdir -p .build
xcrun swiftc -parse-as-library \
  Sources/Trace/Models.swift Sources/Trace/BasicScanner.swift \
  Sources/Trace/AdvancedScanner.swift \
  scripts/ScannerSmoke.swift -o .build/trace-smoke \
  -framework SwiftUI -framework AVFoundation -framework CryptoKit \
  -framework ImageIO -framework PDFKit -framework Security \
  -framework UniformTypeIdentifiers
.build/trace-smoke
```

Checks cover text metadata, the text-sampling boundary, permission findings, hashes, identifier detection, and unsafe ZIP paths. Fixtures are generated at runtime; personal sample files are not included.

`scripts/TrainingInventory.swift` is an optional command-line inventory utility. Compile it in place of `scripts/ScannerSmoke.swift` above and pass a folder path. Its output includes inspected metadata, so review it before sharing.

If the compiler reports SDK mismatches or Swift Package Manager reports missing `llbuild` symbols, inspect `swift --version` and `xcode-select -p`, then select a compatible Apple toolchain. The direct build script and smoke test bypass Swift Package Manager.

## Source layout

```text
Sources/Trace/
  TraceApp.swift          App entry point and commands
  MainView.swift          SwiftUI interface
  ScanStore.swift         Scan lifecycle, recent files, report copying
  Models.swift            Metadata, findings, scan results and styling
  BasicScanner.swift      Filesystem and common-format inspection
  AdvancedScanner.swift   Integrity, provenance and deeper format checks
Tests/TraceTests/         Scanner regression tests
Support/Info.plist        App bundle metadata
scripts/                  Direct app build and scanner utilities
```
