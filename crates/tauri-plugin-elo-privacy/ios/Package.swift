// swift-tools-version:5.9
import PackageDescription
let package = Package(
    name: "tauri-plugin-elo-privacy",
    platforms: [.iOS(.v15)],
    products: [.library(name: "tauri-plugin-elo-privacy", type: .static, targets: ["EloPrivacy"])],
    dependencies: [.package(name: "Tauri", path: "../.tauri/tauri-api")],
    targets: [.target(name: "EloPrivacy", dependencies: [.byName(name: "Tauri")], path: "Sources")]
)
