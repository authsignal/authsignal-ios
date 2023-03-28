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
      targets: ["Authsignal"])
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0")
  ],
  targets: [
    .target(
      name: "Authsignal",
      dependencies: [
        .product(name: "Logging", package: "swift-log")
      ])
  ]
)
