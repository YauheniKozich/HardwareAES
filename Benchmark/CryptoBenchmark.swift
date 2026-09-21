import Foundation
import CommonCrypto
import HardwareAESCore
import HardwareAES

// ============================================================================
// Результат одного прогона бенчмарка.
// ============================================================================
public struct BenchmarkResult: CustomStringConvertible {
    public let name: String
    public let iterations: Int
    public let dataSize: Int
    public let inPlace: Bool

    /// Времена одной операции в секундах, отсортированы по возрастанию.
    /// Для мелких размеров это уже время, нормированное на batchSize.
    public let samples: [Double]

    public var median: Double { samples[samples.count / 2] }
    public var minTime: Double { samples.first! }
    public var p95: Double    { samples[Int(Double(samples.count) * 0.95)] }
    public var mean: Double   { samples.reduce(0, +) / Double(samples.count) }

    /// Throughput на основе медианы (устойчив к выбросам).
    public var throughputMBps: Double {
        Double(dataSize) / median / (1024.0 * 1024.0)
    }

    /// Пиковый throughput (лучший случай — «потолок» железа).
    public var peakThroughputMBps: Double {
        Double(dataSize) / minTime / (1024.0 * 1024.0)
    }

    public var msPerOp: Double { median * 1000.0 }
    public var latencyString: String { Self.formatDuration(median) }

    private var p95LatencyString: String { Self.formatDuration(p95) }
    private var minLatencyString: String { Self.formatDuration(minTime) }

    private static func formatDuration(_ seconds: Double) -> String {
        let nanoseconds = seconds * 1_000_000_000
        if nanoseconds < 1_000 {
            return String(format: "%.2f ns", nanoseconds)
        }

        let microseconds = nanoseconds / 1_000
        if microseconds < 1_000 {
            return String(format: "%.2f µs", microseconds)
        }

        return String(format: "%.2f ms", microseconds / 1_000)
    }

    public var bytesPerOp: Double { Double(dataSize) }

    /// Компактное отображение размера: «256 B», «1.0 KB», «4.0 MB».
    public var sizeString: String {
        if dataSize < 1024 {
            return "\(dataSize) B"
        } else if dataSize < 1024 * 1024 {
            return String(format: "%.1f KB", Double(dataSize) / 1024.0)
        } else {
            return String(format: "%.1f MB", Double(dataSize) / (1024.0 * 1024.0))
        }
    }

    public var description: String {
        String(format: "%@: median %.2f MiB/s, peak %.2f MiB/s (%d iters%@)",
               name, throughputMBps, peakThroughputMBps, iterations,
               inPlace ? ", in-place" : "")
    }

    public var detailedDescription: String {
        let mode = inPlace ? "in-place" : "out-of-place"
        return String(format: "%@ (%@, %@): median %.2f MiB/s, peak %.2f MiB/s, p95 %@, min %@ (%d iters)",
                      name, sizeString, mode,
                      throughputMBps, peakThroughputMBps,
                      p95LatencyString, minLatencyString,
                      iterations)
    }

    public init(name: String,
                iterations: Int,
                dataSize: Int,
                inPlace: Bool,
                samples: [Double]) {
        precondition(!samples.isEmpty, "samples must not be empty")
        self.name       = name
        self.iterations = iterations
        self.dataSize   = dataSize
        self.inPlace    = inPlace
        self.samples    = samples.sorted()
    }
}

// ============================================================================
// Бенчмарк-сьют.
// ============================================================================
public struct CryptoBenchmark {

    /// Кеш timebase: системный вызов делается один раз за жизнь процесса.
    private static let ticksToNanos: Double = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return Double(info.numer) / Double(info.denom)
    }()

    /// Разрешение таймера в наносекундах (типично ~41.67 нс на M1/M2).
    private static let timerResolutionNanos: Double = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return Double(info.denom) / Double(info.numer)
    }()

    /// Размеры для замера: L1 (256 B–16 KB), L2 (256 KB–4 MB), SLC/DRAM (16–100 MB).
    public static let defaultSizes: [(String, Int)] = [
        ("256B",   256),
        ("1KB",    1024),
        ("4KB",    4 * 1024),
        ("16KB",   16 * 1024),
        ("64KB",   64 * 1024),
        ("256KB",  256 * 1024),
        ("1MB",    1024 * 1024),
        ("4MB",    4 * 1024 * 1024),
        ("16MB",   16 * 1024 * 1024),
        ("64MB",   64 * 1024 * 1024),
        ("100MB",  100 * 1024 * 1024),
    ]

    private let targetSeconds: Double
    private let maxIterations: Int
    private let minIterations: Int

    public init(targetSeconds: Double = 0.5,
                maxIterations: Int = 50_000,
                minIterations: Int = 5) {
        self.targetSeconds = targetSeconds
        self.maxIterations = maxIterations
        self.minIterations = minIterations
    }

    /// Удобный init для обратной совместимости со старым API.
    /// `iterations` трактуется как нижний предел, целевое время — 0.5 с.
    public init(iterations: Int) {
        self.init(targetSeconds: 0.5,
                  maxIterations: max(iterations, 50_000),
                  minIterations: iterations)
    }

    public func run(sizes: [(String, Int)] = CryptoBenchmark.defaultSizes) -> [String: BenchmarkResult] {
        var results: [String: BenchmarkResult] = [:]
        for (label, size) in sizes {
            results[label] = benchmarkCTR(dataSize: size, name: "CTR \(label)", inPlace: false)
            results[label + "_inplace"] = benchmarkCTR(dataSize: size, name: "CTR \(label)", inPlace: true)
        }
        return results
    }

    /// Measures CommonCrypto as an independent API reference.
    ///
    /// Each operation includes cryptor creation and update, so this is an API
    /// reference rather than a pure AES-core comparison.
    public func runCommonCrypto(
        sizes: [(String, Int)] = CryptoBenchmark.defaultSizes
    ) -> [String: BenchmarkResult] {
        var results: [String: BenchmarkResult] = [:]
        for (label, size) in sizes {
            results[label] = benchmarkCommonCrypto(
                dataSize: size,
                name: "CommonCrypto CTR \(label)"
            )
        }
        return results
    }

    // ------------------------------------------------------------------
    // Оценка числа итераций по целевому времени.
    // ------------------------------------------------------------------
    private func iterationsFor(dataSize: Int) -> Int {
        let assumedBytesPerSecond = 15.0 * 1024 * 1024 * 1024
        let raw = targetSeconds * assumedBytesPerSecond / Double(dataSize)
        return max(minIterations, min(maxIterations, Int(raw)))
    }

    /// Размер пачки: сколько операций выполнять между двумя замерами таймера.
    /// Для мелких размеров одна операция короче разрешения таймера,
    /// поэтому меряем пачку и делим результат.
    private func batchSizeFor(dataSize: Int) -> Int {
        // Оценка времени одной операции.
        let assumedBytesPerSecond = 15.0 * 1024 * 1024 * 1024
        let estimatedSecondsPerOp = Double(dataSize) / assumedBytesPerSecond
        let estimatedNanosPerOp = estimatedSecondsPerOp * 1_000_000_000

        // Хотим, чтобы пачка занимала минимум ~10 мкс (240+ тиков таймера).
        let minBatchNanos = 10_000.0
        if estimatedNanosPerOp >= minBatchNanos {
            return 1
        }
        let raw = minBatchNanos / estimatedNanosPerOp
        // Округляем до ближайшей степени десятки для читаемости.
        if raw < 10 { return 10 }
        if raw < 100 { return 100 }
        if raw < 1000 { return 1000 }
        return 10_000
    }

    private func benchmarkCTR(dataSize: Int,
                              name: String,
                              inPlace: Bool) -> BenchmarkResult {
        let key: SecureKey
        let engine: HardwareAES
        let iv: AESIV
        do {
            key    = try SecureKey(Data(repeating: 0x42, count: 16))
            engine = try HardwareAES(key: key)
            iv     = try AESIV(Data(repeating: 0x01, count: 16))
        } catch {
            preconditionFailure("Benchmark setup failed: \(error)")
        }

        let batchSize  = batchSizeFor(dataSize: dataSize)
        let totalIters = iterationsFor(dataSize: dataSize)
        let batchCount = max(1, totalIters / batchSize)
        let mode       = AESMode.ctr(iv: iv)
        let warmup     = dataSize >= 8 * 1024 * 1024 ? 1 : 3

        var samples = [Double]()
        samples.reserveCapacity(batchCount)

        var checksum: UInt64 = 0

        if inPlace {
            // Rotate across independent buffers so the benchmark does not
            // force every operation to consume the bytes written immediately
            // by the previous operation. Keep the ring bounded for large
            // buffers to avoid turning the benchmark into a memory test.
            let ringCount = min(64, max(2, (256 * 1024 * 1024) / max(dataSize, 1)))
            var bufferRing = (0..<ringCount).map { _ in
                Data(repeating: 0x41, count: dataSize)
            }
            var operationIndex = 0

            for _ in 0..<warmup {
                let bufferIndex = operationIndex % ringCount
                try? engine.encryptInPlace(&bufferRing[bufferIndex], mode: mode)
                operationIndex += 1
            }

            for _ in 0..<batchCount {
                let t0 = mach_absolute_time()
                autoreleasepool {
                    for _ in 0..<batchSize {
                        let bufferIndex = operationIndex % ringCount
                        do {
                            try engine.encryptInPlace(&bufferRing[bufferIndex], mode: mode)
                        } catch {
                            preconditionFailure("In-place encrypt failed: \(error)")
                        }
                        operationIndex += 1
                    }
                }
                let dt = Double(mach_absolute_time() - t0) * Self.ticksToNanos
                samples.append(dt / Double(batchSize) / 1_000_000_000)
            }
            for buffer in bufferRing {
                checksum &+= consume(buffer)
            }
        } else {
            let plaintext  = Data(repeating: 0x41, count: dataSize)
            var ciphertext = Data(count: dataSize)

            try? plaintext.withUnsafeBytes { inBuf in
                try ciphertext.withUnsafeMutableBytes { outBuf in
                    for _ in 0..<warmup {
                        try engine.encrypt(input: inBuf, output: outBuf, mode: mode)
                    }
                    for _ in 0..<batchCount {
                        let t0 = mach_absolute_time()
                        for _ in 0..<batchSize {
                            try engine.encrypt(input: inBuf, output: outBuf, mode: mode)
                        }
                        let dt = Double(mach_absolute_time() - t0) * Self.ticksToNanos
                        samples.append(dt / Double(batchSize) / 1_000_000_000)
                    }
                }
            }
            checksum = consume(ciphertext)
        }

        // Keep the benchmark honest: the output is consumed after timing so
        // the measured region contains only encryption work and not checksum
        // traversal, while the optimizer still cannot discard the writes.
        if checksum == UInt64.max {
            preconditionFailure("Benchmark checksum sentinel reached")
        }

        return BenchmarkResult(name: name,
                               iterations: batchCount * batchSize,
                               dataSize: dataSize,
                               inPlace: inPlace,
                               samples: samples)
    }

    private func benchmarkCommonCrypto(dataSize: Int,
                                       name: String) -> BenchmarkResult {
        let key = Data(repeating: 0x42, count: 16)
        let iv = Data(repeating: 0x01, count: 16)
        let plaintext = Data(repeating: 0x41, count: dataSize)
        var ciphertext = Data(count: dataSize)

        var cryptor: CCCryptorRef?
        let createStatus = key.withUnsafeBytes { keyBuffer in
            iv.withUnsafeBytes { ivBuffer in
                CCCryptorCreateWithMode(
                    CCOperation(kCCEncrypt),
                    CCMode(kCCModeCTR),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding),
                    ivBuffer.baseAddress,
                    keyBuffer.baseAddress,
                    key.count,
                    nil,
                    0,
                    0,
                    CCModeOptions(kCCModeOptionCTR_BE),
                    &cryptor
                )
            }
        }
        guard createStatus == CCCryptorStatus(kCCSuccess),
              let cryptor else {
            preconditionFailure("CommonCrypto cryptor creation failed: \(createStatus)")
        }
        defer { CCCryptorRelease(cryptor) }

        let batchSize = batchSizeFor(dataSize: dataSize)
        let totalIters = iterationsFor(dataSize: dataSize)
        let batchCount = max(1, totalIters / batchSize)
        let warmup = dataSize >= 8 * 1024 * 1024 ? 1 : 3

        func encryptOnce() {
            var moved = 0
            let status = ciphertext.withUnsafeMutableBytes { outputBuffer in
                plaintext.withUnsafeBytes { inputBuffer in
                    CCCryptorUpdate(
                        cryptor,
                        inputBuffer.baseAddress,
                        dataSize,
                        outputBuffer.baseAddress,
                        dataSize,
                        &moved
                    )
                }
            }
            guard status == CCCryptorStatus(kCCSuccess), moved == dataSize else {
                preconditionFailure("CommonCrypto encryption failed: \(status)")
            }
        }

        for _ in 0..<warmup {
            encryptOnce()
        }

        var samples = [Double]()
        samples.reserveCapacity(batchCount)

        for _ in 0..<batchCount {
            let t0 = mach_absolute_time()
            for _ in 0..<batchSize {
                encryptOnce()
            }
            let dt = Double(mach_absolute_time() - t0) * Self.ticksToNanos
            samples.append(dt / Double(batchSize) / 1_000_000_000)
        }

        if consume(ciphertext) == UInt64.max {
            preconditionFailure("Benchmark checksum sentinel reached")
        }

        return BenchmarkResult(name: name,
                               iterations: batchCount * batchSize,
                               dataSize: dataSize,
                               inPlace: false,
                               samples: samples)
    }

    @inline(never)
    private func consume(_ data: Data) -> UInt64 {
        data.withUnsafeBytes { buffer in
            var result: UInt64 = 1469598103934665603
            for byte in buffer {
                result = (result &* 1099511628211) ^ UInt64(byte)
            }
            return result
        }
    }
}

// ============================================================================
// Сравнение двух результатов.
// ============================================================================
public func compareResults(baseline: BenchmarkResult, optimized: BenchmarkResult) {
    guard baseline.throughputMBps > 0, optimized.throughputMBps > 0 else {
        print("\n=== Cannot compare \(baseline.name): zero throughput ===")
        return
    }

    let speedup     = optimized.throughputMBps / baseline.throughputMBps
    let improvement = (speedup - 1.0) * 100.0

    print("\n=== Performance Comparison: \(baseline.name) ===")
    print(String(format: "Baseline:   %.2f MiB/s (median)", baseline.throughputMBps))
    print(String(format: "Optimized:  %.2f MiB/s (median)", optimized.throughputMBps))
    print(String(format: "Speedup:    %.2fx (%.1f%% %@)",
                 speedup, abs(improvement),
                 improvement >= 0 ? "improvement" : "regression"))
}
