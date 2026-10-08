// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "EloDiagnostics",
    platforms: [.iOS(.v16), .macOS(.v11)],
    products: [.library(name: "EloDiagnostics", type: .static, targets: ["EloDiagnostics"])],
    dependencies: [
        .package(url: "https://github.com/firebase/firebase-ios-sdk.git", exact: "12.19.2"),
        .package(url: "https://github.com/google/GoogleUtilities.git", exact: "8.1.3")
    ],
    targets: [.target(name: "EloDiagnostics", dependencies: [
        .product(name: "FirebaseCrashlytics", package: "firebase-ios-sdk"),
        .product(name: "GULNSData", package: "GoogleUtilities")
    ])]
)
