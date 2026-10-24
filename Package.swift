// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "Trace",
    platforms: [
        .macOS(.v14)
    ],
    products: [
        .executable(name: "Trace", targets: ["Trace"])
    ],
    targets: [
        .executableTarget(
            name: "Trace",
            path: "Sources/Trace"
        ),
        .testTarget(
            name: "TraceTests",
            dependencies: ["Trace"],
            path: "Tests/TraceTests"
        )
    ]
)
