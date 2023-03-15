// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Authsignal",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(
            name: "Authsignal",
            targets: ["Authsignal"]),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "Authsignal",
            dependencies: []),
    ]
)
