// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "CLISpoofShieldKit",
    platforms: [
        .iOS(.v16),
        .macOS(.v13)
    ],
    products: [
        .library(
            name: "CLISpoofShieldKit",
            targets: ["CLISpoofShieldKit"]
        )
    ],
    targets: [
        .target(
            name: "CLISpoofShieldKit",
            path: "Shared",
            linkerSettings: [
                .linkedLibrary("sqlite3")
            ]
        )
    ]
)
