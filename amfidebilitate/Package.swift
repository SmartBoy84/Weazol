// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "amfidebilitate",
    platforms: [
        .iOS(.v14),
        .macOS(.v11),
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .executable(
            name: "amfidebilitate",
            targets: ["amfidebilitate"]
        ),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(path: "Sources/KernelExploit"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .systemLibrary(name: "externalCStuff"),
        .target(name: "asmAndC"),
        .target(name: "amfiC"),
        .target(
            name: "amfidebilitate",
            dependencies: ["KernelExploit", "externalCStuff", "asmAndC", "amfiC"]
        ),
    ]
)
