// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "HardwareAESEngine",
    platforms: [
        .iOS(.v15),
        .macOS(.v12)
    ],
    products: [
        .library(name: "HardwareAESCore", targets: ["HardwareAESCore"]),
        .library(name: "HardwareAESCTR", targets: ["HardwareAESCTR"]),
        .library(name: "HardwareAESAuthenticated", targets: ["HardwareAESAuthenticated"]),
        // Главный зонтичный фреймворк для интеграции в приложение
        .library(name: "HardwareAES", targets: ["HardwareAESCore", "HardwareAESCTR", "HardwareAES"])
    ],
    targets: [
        // 1. Низкоуровневый Си-код с инлайн-ассемблером ARM NEON. Накатываем максимальный буст.
        .target(
            name: "HardwareAESASM",
            path: "Assembly",
            sources: [
                "Common/aes_key_expansion.c",
                "Common/aes_secure_zero.c",
                "Common/aes_selftest.c",
                "CTR/aes_ctr.c",
                "ECB/aes_ecb.c"
            ],
            publicHeadersPath: "include",
            cSettings: []
        ),
        
        // 2. Базовые типы данных (SecureKey, AESIV, AESMode)
        .target(
            name: "HardwareAESCore",
            dependencies: ["HardwareAESASM"],
            path: "Core",
            exclude: ["HardwareAES.swift"],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
        
        // 3. Режим CTR (Теперь явно видит Си-функции из HardwareAESASM)
        .target(
            name: "HardwareAESCTR",
            dependencies: ["HardwareAESCore", "HardwareAESASM"], // Исправлено: добавлена зависимость от ASM
            path: "Modes/CTR",
            exclude: ["README.md"],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
        
        // Internal AES block primitive used by CMAC and known-answer tests.
        .target(
            name: "HardwareAESBlockCipher",
            dependencies: ["HardwareAESCore", "HardwareAESASM"],
            path: "Primitives",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),

        .target(
            name: "HardwareAESAuthenticated",
            dependencies: ["HardwareAESCore", "HardwareAESCTR", "HardwareAESBlockCipher", "HardwareAESASM"],
            path: "Authenticated",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
        
        // 5. Фасадный модуль HardwareAES
        .target(
            name: "HardwareAES",
            dependencies: [
                "HardwareAESCore",
                "HardwareAESCTR"
            ],
            path: "Core",
            exclude: [
                "AESMode.swift",
                "HardwareAESEngineProtocol.swift",
                "SecureKey.swift"
            ],
            sources: ["HardwareAES.swift"],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
        
        // MARK: - Бенчмарки и Тесты
        
        .target(
            name: "HardwareAESBenchmark",
            dependencies: ["HardwareAES", "HardwareAESCTR", "HardwareAESASM"],
            path: "Benchmark",
            exclude: ["main.swift"],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency")
            ]
        ),
        
        // Исполняемый CLI-плагин для запуска через терминал `swift run`
        .executableTarget(
            name: "HardwareAESBenchmarkCLI",
            dependencies: ["HardwareAESBenchmark"],
            path: "Benchmark",
            exclude: [
                "CryptoBenchmark.swift",
                "SideChannelTest.swift",
                "CorrectnessValidation.swift"
            ],
            sources: ["main.swift"],
            swiftSettings: []
        ),
        
        .testTarget(
            name: "HardwareAESCoreTests",
            dependencies: ["HardwareAESCore"],
            path: "Tests",
            exclude: ["HardwareAESCTRTests.swift", "HardwareAESBlockCipherTests.swift", "HardwareAESAuthenticatedTests.swift"],
            sources: ["HardwareAESCoreTests.swift"]
        ),
        
        .testTarget(
            name: "HardwareAESCTRTests",
            dependencies: ["HardwareAESCore", "HardwareAESCTR", "HardwareAESASM", "HardwareAES"],
            path: "Tests",
            exclude: ["HardwareAESCoreTests.swift", "HardwareAESBlockCipherTests.swift", "HardwareAESAuthenticatedTests.swift"],
            sources: ["HardwareAESCTRTests.swift"]
        ),
        
        .testTarget(
            name: "HardwareAESBlockCipherTests",
            dependencies: ["HardwareAESCore", "HardwareAESBlockCipher"],
            path: "Tests",
            exclude: ["HardwareAESCoreTests.swift", "HardwareAESCTRTests.swift", "HardwareAESAuthenticatedTests.swift"],
            sources: ["HardwareAESBlockCipherTests.swift"]
        ),

        .testTarget(
            name: "HardwareAESAuthenticatedTests",
            dependencies: ["HardwareAESCore", "HardwareAESCTR", "HardwareAESAuthenticated"],
            path: "Tests",
            exclude: ["HardwareAESCoreTests.swift", "HardwareAESCTRTests.swift", "HardwareAESBlockCipherTests.swift"],
            sources: ["HardwareAESAuthenticatedTests.swift"]
        )
    ]
)
