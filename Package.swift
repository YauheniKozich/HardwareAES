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
        .library(name: "HardwareAESECB", targets: ["HardwareAESECB"]),
        // Главный зонтичный фреймворк для интеграции в приложение
        .library(name: "HardwareAES", targets: ["HardwareAESCore", "HardwareAESCTR", "HardwareAESECB", "HardwareAES"])
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
            cSettings: [
                .unsafeFlags([
                    "-O3"                       // Максимальный уровень оптимизации Clang
                ])
            ]
        ),
        
        // 2. Базовые типы данных (SecureKey, AESIV, AESMode)
        .target(
            name: "HardwareAESCore",
            dependencies: ["HardwareAESASM"],
            path: "Core",
            exclude: ["HardwareAES.swift"],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
                .unsafeFlags(["-O"]) // Гарантируем Release-оптимизацию для Swift-слоя
            ]
        ),
        
        // 3. Режим CTR (Теперь явно видит Си-функции из HardwareAESASM)
        .target(
            name: "HardwareAESCTR",
            dependencies: ["HardwareAESCore", "HardwareAESASM"], // Исправлено: добавлена зависимость от ASM
            path: "Modes/CTR",
            exclude: ["README.md"],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
                .unsafeFlags(["-O"])
            ]
        ),
        
        // 4. Режим ECB (Также явно подключаем к Си-модулю)
        .target(
            name: "HardwareAESECB",
            dependencies: ["HardwareAESCore", "HardwareAESASM"], // Исправлено: добавлена зависимость от ASM
            path: "Modes/ECB",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
                .unsafeFlags(["-O"])
            ]
        ),
        
        // 5. Фасадный модуль HardwareAES
        .target(
            name: "HardwareAES",
            dependencies: [
                "HardwareAESCore",
                "HardwareAESCTR",
                "HardwareAESECB"
            ],
            path: "Core",
            exclude: [
                "AESMode.swift",
                "HardwareAESEngineProtocol.swift",
                "SecureFileVault.swift",
                "SecureKey.swift"
            ],
            sources: ["HardwareAES.swift"],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
                .unsafeFlags(["-O"])
            ]
        ),
        
        // MARK: - Бенчмарки и Тесты
        
        .target(
            name: "HardwareAESBenchmark",
            dependencies: ["HardwareAES", "HardwareAESCTR", "HardwareAESASM"],
            path: "Benchmark",
            exclude: ["main.swift"],
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
                .unsafeFlags(["-O"])
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
            swiftSettings: [.unsafeFlags(["-O"])]
        ),
        
        .testTarget(
            name: "HardwareAESCoreTests",
            dependencies: ["HardwareAESCore"],
            path: "Tests",
            exclude: ["HardwareAESCTRTests.swift", "HardwareAESECCTests.swift"],
            sources: ["HardwareAESCoreTests.swift"]
        ),
        
        .testTarget(
            name: "HardwareAESCTRTests",
            dependencies: ["HardwareAESCore", "HardwareAESCTR", "HardwareAESASM"],
            path: "Tests",
            exclude: ["HardwareAESCoreTests.swift", "HardwareAESECCTests.swift"],
            sources: ["HardwareAESCTRTests.swift"]
        ),
        
        .testTarget(
            name: "HardwareAESECCTests",
            dependencies: ["HardwareAESCore", "HardwareAESCTR", "HardwareAESECB"],
            path: "Tests",
            exclude: ["HardwareAESCoreTests.swift", "HardwareAESCTRTests.swift"],
            sources: ["HardwareAESECCTests.swift"]
        )
    ]
)
