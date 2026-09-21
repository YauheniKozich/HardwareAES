import Foundation
import HardwareAESBenchmark
import HardwareAESCore
import HardwareAESCTR

print("")
print("╔════════════════════════════════════════════════════════╗")
print("║     HardwareAES CTR Mode Performance Benchmark         ║")
print("║          (8-Way Interleaving Optimized)                ║")
print("╚════════════════════════════════════════════════════════╝")
print("")

let cryptoBenchmark = CryptoBenchmark(targetSeconds: 0.5)
let correctness = cryptoBenchmark.validateCorrectness()
print("🧪 Correctness Validation")
print(correctness.summary)
print("")
guard correctness.passed else {
    exit(1)
}

let cryptoResults = DispatchQueue.global(qos: .userInteractive).sync {
    cryptoBenchmark.run()
}
let commonCryptoResults = DispatchQueue.global(qos: .userInteractive).sync {
    cryptoBenchmark.runCommonCrypto()
}

// ---------------------------------------------------------------------------
// Detailed results
// ---------------------------------------------------------------------------
print("📊 Detailed Results (8-Way Instruction-Level Parallelism):")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
for result in cryptoResults.values.sorted(by: {
    if $0.dataSize != $1.dataSize {
        return $0.dataSize < $1.dataSize
    }
    return !$0.inPlace && $1.inPlace
}) {
    print(result.detailedDescription)
}
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
print("")

// ---------------------------------------------------------------------------
// Summary table
//
// Ширины колонок подобраны под максимальные значения:
//   Data Size   : "256 B" (5), "100.0 MB" (8)          → 12
//   Throughput  : "2611.13 MiB/s" (13), "10000.00 MiB/s" (14) → 15
//   Time/op     : "0.0001 ms" (9), "11.2074 ms" (10)    → 11
// ---------------------------------------------------------------------------
let colSize = 16
let colThr = 15
let colLat = 11
let sepTop = "┌" + String(repeating: "─", count: colSize + 2)
    + "┬" + String(repeating: "─", count: colThr + 2)
    + "┬" + String(repeating: "─", count: colLat + 2) + "┐"
let sepMiddle = "├" + String(repeating: "─", count: colSize + 2)
    + "┼" + String(repeating: "─", count: colThr + 2)
    + "┼" + String(repeating: "─", count: colLat + 2) + "┤"
let sepBottom = "└" + String(repeating: "─", count: colSize + 2)
    + "┴" + String(repeating: "─", count: colThr + 2)
    + "┴" + String(repeating: "─", count: colLat + 2) + "┘"
let headerSize = "Data Size".padding(toLength: colSize, withPad: " ", startingAt: 0)
let headerThr = "Throughput".padding(toLength: colThr, withPad: " ", startingAt: 0)
let headerLat = "Time/op".padding(toLength: colLat, withPad: " ", startingAt: 0)

print("📈 Performance Summary Table:")
print(sepTop)
print("│ " + headerSize + " │ " + headerThr + " │ " + headerLat + " │")
print(sepMiddle)
for result in cryptoResults.values.sorted(by: {
    if $0.dataSize != $1.dataSize {
        return $0.dataSize < $1.dataSize
    }
    return !$0.inPlace && $1.inPlace
}) {
    let modeTag = result.inPlace ? " (in)" : " (out)"
    let size = (result.sizeString + modeTag)
        .padding(toLength: colSize, withPad: " ", startingAt: 0)
    let thr = String(format: "%.2f MiB/s", result.throughputMBps)
        .padding(toLength: colThr, withPad: " ", startingAt: 0)
    let lat = result.latencyString
        .padding(toLength: colLat, withPad: " ", startingAt: 0)
    print("│ " + size + " │ " + thr + " │ " + lat + " │")
}
print(sepBottom)
print("")

print("📎 CommonCrypto Reference (steady-state update):")
print("┌──────────────┬─────────────────┬─────────────────┐")
print("│ Data Size    │ HardwareAES     │ CommonCrypto    │")
print("├──────────────┼─────────────────┼─────────────────┤")
for hardware in cryptoResults.values
    .filter({ !$0.inPlace })
    .sorted(by: { $0.dataSize < $1.dataSize }) {
    guard let reference = commonCryptoResults.values.first(where: {
        $0.dataSize == hardware.dataSize
    }) else {
        continue
    }
    let size = hardware.sizeString.padding(toLength: 12, withPad: " ", startingAt: 0)
    let hardwareThroughput = String(format: "%.2f MiB/s", hardware.throughputMBps)
        .padding(toLength: 15, withPad: " ", startingAt: 0)
    let commonCryptoThroughput = String(format: "%.2f MiB/s", reference.throughputMBps)
        .padding(toLength: 15, withPad: " ", startingAt: 0)
    print("│ " + size + " │ " + hardwareThroughput + " │ " + commonCryptoThroughput + " │")
}
print("└──────────────┴─────────────────┴─────────────────┘")
print("Note: CommonCrypto uses one reusable cryptor; creation is outside timing.")
print("It is a reference point, not a claim that either implementation is better.")
print("For small messages, any CommonCrypto gap includes its per-call API")
print("overhead; it should not be interpreted as faster AES rounds.")
print("")
print("Architecture Note: the benchmark now rotates in-place work across an")
print("independent buffer ring. Any remaining in/out gap is an observation,")
print("not evidence of a specific microarchitectural cause.")
print("")
print("✅ Benchmark execution complete!")
print("")
print("Нажмите [ENTER], чтобы закрыть это окно...")
_ = readLine()
