// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "tauri-plugin-elo-push",
    platforms: [.iOS(.v15), .macOS(.v10_15)],
    products: [.library(name: "tauri-plugin-elo-push", type: .static, targets: ["EloPush"])],
    dependencies: [
        .package(name: "Tauri", path: "../.tauri/tauri-api"),
        .package(url: "https://github.com/firebase/firebase-ios-sdk.git", exact: "12.19.2"),
        .package(url: "https://github.com/google/GoogleUtilities.git", exact: "8.1.3"),
        .package(url: "https://github.com/stasel/WebRTC.git", exact: "153.0.0")
    ],
    targets: [.target(name: "EloPush", dependencies: [
        .byName(name: "Tauri"),
        .product(name: "FirebaseMessaging", package: "firebase-ios-sdk"),
        .product(name: "GULNSData", package: "GoogleUtilities"),
        .product(name: "WebRTC", package: "WebRTC")
    ], path: "Sources")]
)
