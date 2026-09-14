// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "tauri-plugin-elo-push",
    platforms: [.iOS(.v15), .macOS(.v10_15)],
    products: [.library(name: "tauri-plugin-elo-push", type: .static, targets: ["EloPush"])],
    dependencies: [
        .package(name: "Tauri", path: "../.tauri/tauri-api"),
        .package(url: "https://github.com/firebase/firebase-ios-sdk.git", exact: "12.18.0"),
        .package(url: "https://github.com/google/GoogleUtilities.git", exact: "8.1.3")
    ],
    targets: [.target(name: "EloPush", dependencies: [
        .byName(name: "Tauri"),
        .product(name: "FirebaseMessaging", package: "firebase-ios-sdk"),
        .product(name: "GULNSData", package: "GoogleUtilities")
    ], path: "Sources")]
)
