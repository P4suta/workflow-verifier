// SPDX-License-Identifier: MIT OR Apache-2.0
// This signed process is the complete Apple-framework ownership boundary. It
// receives canonical JSON only and contains no analyzer or policy-engine code.

import CryptoKit
import Darwin
import Foundation
import Virtualization

private let requestSchema = "vm-shim-request-v1"
private let observationSchema = "vm-observation-v1"
private let manifestSchema = "vm-image-v1"

private struct VmImage: Decodable {
    let architecture: String
    let kernelPath: String
    let kernelDigest: String
    let initrdPath: String
    let initrdDigest: String
    let rootfsPath: String
    let rootfsDigest: String
    let manifestDigest: String

    enum CodingKeys: String, CodingKey {
        case architecture
        case kernelPath = "kernel_path"
        case kernelDigest = "kernel_digest"
        case initrdPath = "initrd_path"
        case initrdDigest = "initrd_digest"
        case rootfsPath = "rootfs_path"
        case rootfsDigest = "rootfs_digest"
        case manifestDigest = "manifest_digest"
    }
}

private struct VmRequest: Decodable {
    let schema: String
    let planDigest: String
    let image: VmImage
    let sourceRoot: String
    let scratchRoot: String
    let controlRoot: String
    let workingDirectory: String
    let argv: [String]
    let environment: [String: String]
    let cpuCount: UInt64
    let memoryMb: UInt64
    let processes: UInt64
    let timeoutSeconds: UInt64
    let outputBytes: UInt64
    let network: Bool

    enum CodingKeys: String, CodingKey {
        case schema, image, argv, environment, processes, network
        case planDigest = "plan_digest"
        case sourceRoot = "source_root"
        case scratchRoot = "scratch_root"
        case controlRoot = "control_root"
        case workingDirectory = "working_directory"
        case cpuCount = "cpu_count"
        case memoryMb = "memory_mb"
        case timeoutSeconds = "timeout_seconds"
        case outputBytes = "output_bytes"
    }
}

private struct ImageManifest: Decodable {
    let schema: String
    let architecture: String
    let kernelDigest: String
    let initrdDigest: String
    let rootfsDigest: String
    let agentDigest: String
    let version: String

    enum CodingKeys: String, CodingKey {
        case schema, architecture, version
        case kernelDigest = "kernel_digest"
        case initrdDigest = "initrd_digest"
        case rootfsDigest = "rootfs_digest"
        case agentDigest = "agent_digest"
    }
}

private enum ShimFailure: LocalizedError {
    case message(String)

    var errorDescription: String? {
        switch self {
        case .message(let value): return value
        }
    }
}

private func fail(_ message: String) throws -> Never {
    throw ShimFailure.message(message)
}

private func validateExactKeys(
    _ object: [String: Any],
    expected: Set<String>,
    context: String
) throws {
    let actual = Set(object.keys)
    guard actual == expected else {
        try fail("\(context) keys are \(actual.sorted()), expected \(expected.sorted())")
    }
}

private func regularFile(_ path: String, context: String) throws -> URL {
    let original = URL(fileURLWithPath: path).standardizedFileURL
    let values = try original.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
    guard values.isRegularFile == true, values.isSymbolicLink != true else {
        try fail("\(context) must be a regular non-symlink file")
    }
    let canonical = original.resolvingSymlinksInPath().standardizedFileURL
    guard canonical.path == original.path else {
        try fail("\(context) may not traverse a symlink")
    }
    return canonical
}

private func directory(_ path: String, context: String) throws -> URL {
    let original = URL(fileURLWithPath: path).standardizedFileURL
    let values = try original.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
    guard values.isDirectory == true, values.isSymbolicLink != true else {
        try fail("\(context) must be a non-symlink directory")
    }
    let canonical = original.resolvingSymlinksInPath().standardizedFileURL
    guard canonical.path == original.path else {
        try fail("\(context) may not traverse a symlink")
    }
    return canonical
}

private func sha256(_ url: URL) throws -> String {
    let handle = try FileHandle(forReadingFrom: url)
    defer { try? handle.close() }
    var digest = SHA256()
    while true {
        guard let data = try handle.read(upToCount: 128 * 1024), !data.isEmpty else { break }
        digest.update(data: data)
    }
    return "sha256:" + digest.finalize().map { String(format: "%02x", $0) }.joined()
}

private func verifyDigest(_ path: String, expected: String, context: String) throws {
    let actual = try sha256(regularFile(path, context: context))
    guard actual == expected else {
        try fail("\(context) digest mismatch: expected \(expected), actual \(actual)")
    }
}

private func decodeRequest(_ path: String) throws -> (VmRequest, Data) {
    let requestUrl = try regularFile(path, context: "VM request")
    let attributes = try FileManager.default.attributesOfItem(atPath: requestUrl.path)
    let size = (attributes[.size] as? NSNumber)?.uint64Value ?? UInt64.max
    guard size <= 4 * 1024 * 1024 else { try fail("VM request exceeds 4 MiB") }
    let data = try Data(contentsOf: requestUrl, options: .mappedIfSafe)
    let root = try JSONSerialization.jsonObject(with: data)
    guard let object = root as? [String: Any] else { try fail("VM request must be an object") }
    try validateExactKeys(
        object,
        expected: [
            "argv", "control_root", "cpu_count", "environment", "image", "memory_mb",
            "network", "output_bytes", "plan_digest", "processes", "schema",
            "scratch_root", "source_root", "timeout_seconds", "working_directory",
        ],
        context: "VM request"
    )
    guard let image = object["image"] as? [String: Any] else {
        try fail("VM image must be an object")
    }
    try validateExactKeys(
        image,
        expected: [
            "architecture", "initrd_digest", "initrd_path", "kernel_digest",
            "kernel_path", "manifest_digest", "rootfs_digest", "rootfs_path",
        ],
        context: "VM image"
    )
    let request = try JSONDecoder().decode(VmRequest.self, from: data)
    guard request.schema == requestSchema else { try fail("unexpected VM request schema") }
    guard !request.network else { try fail("VM network must remain disabled") }
    guard !request.argv.isEmpty else { try fail("VM command is empty") }
    guard request.sourceRoot != request.scratchRoot,
          request.sourceRoot != request.controlRoot,
          request.scratchRoot != request.controlRoot else {
        try fail("VM shared roots must be distinct")
    }
    guard request.workingDirectory == "/workspace"
            || request.workingDirectory.hasPrefix("/workspace/") else {
        try fail("VM working directory escapes /workspace")
    }
    return (request, data)
}

private func validateImage(_ request: VmRequest) throws {
    #if arch(arm64)
    let hostArchitecture = "arm64"
    #elseif arch(x86_64)
    let hostArchitecture = "x86_64"
    #else
    let hostArchitecture = "unsupported"
    #endif
    guard request.image.architecture == hostArchitecture else {
        try fail("VM image architecture does not match this Mac")
    }
    try verifyDigest(request.image.kernelPath, expected: request.image.kernelDigest, context: "kernel")
    try verifyDigest(request.image.initrdPath, expected: request.image.initrdDigest, context: "initrd")
    try verifyDigest(request.image.rootfsPath, expected: request.image.rootfsDigest, context: "rootfs")

    let bundle = URL(fileURLWithPath: request.image.kernelPath).deletingLastPathComponent()
    let manifestUrl = bundle.appendingPathComponent("manifest.json", isDirectory: false)
    let actualManifestDigest = try sha256(regularFile(manifestUrl.path, context: "manifest"))
    guard actualManifestDigest == request.image.manifestDigest else {
        try fail("manifestDigest mismatch")
    }
    let manifestData = try Data(contentsOf: manifestUrl)
    let root = try JSONSerialization.jsonObject(with: manifestData)
    guard let object = root as? [String: Any] else { try fail("manifest must be an object") }
    try validateExactKeys(
        object,
        expected: [
            "agent_digest", "architecture", "initrd_digest", "kernel_digest",
            "rootfs_digest", "schema", "version",
        ],
        context: "VM manifest"
    )
    let manifest = try JSONDecoder().decode(ImageManifest.self, from: manifestData)
    guard manifest.schema == manifestSchema,
          manifest.architecture == request.image.architecture,
          manifest.kernelDigest == request.image.kernelDigest,
          manifest.initrdDigest == request.image.initrdDigest,
          manifest.rootfsDigest == request.image.rootfsDigest,
          !manifest.version.isEmpty else {
        try fail("manifest does not bind the requested VM image")
    }
    try verifyDigest(
        bundle.appendingPathComponent("workflow-verifier-vm-agent").path,
        expected: manifest.agentDigest,
        context: "guest agent"
    )
}

@available(macOS 13.0, *)
private func directoryShare(tag: String, path: String, readOnly: Bool) throws
    -> VZVirtioFileSystemDeviceConfiguration {
    let shared = VZSharedDirectory(url: try directory(path, context: tag), readOnly: readOnly)
    let device = VZVirtioFileSystemDeviceConfiguration(tag: tag)
    device.share = VZSingleDirectoryShare(directory: shared)
    return device
}

@available(macOS 13.0, *)
private func configuration(for request: VmRequest) throws -> VZVirtualMachineConfiguration {
    try validateImage(request)
    guard request.cpuCount >= 1,
          request.cpuCount <= UInt64(VZVirtualMachineConfiguration.maximumAllowedCPUCount) else {
        try fail("VM CPU count is unsupported")
    }
    let memory = request.memoryMb.multipliedReportingOverflow(by: 1024 * 1024)
    guard !memory.overflow,
          memory.partialValue >= VZVirtualMachineConfiguration.minimumAllowedMemorySize,
          memory.partialValue <= VZVirtualMachineConfiguration.maximumAllowedMemorySize else {
        try fail("VM memory size is unsupported")
    }

    let configuration = VZVirtualMachineConfiguration()
    configuration.platform = VZGenericPlatformConfiguration()
    configuration.cpuCount = Int(request.cpuCount)
    configuration.memorySize = memory.partialValue

    let bootLoader = VZLinuxBootLoader(
        kernelURL: try regularFile(request.image.kernelPath, context: "kernel")
    )
    bootLoader.initialRamdiskURL = try regularFile(request.image.initrdPath, context: "initrd")
    bootLoader.commandLine = [
        "console=hvc0", "panic=-1", "rdinit=/workflow-verifier-vm-agent",
        "workflow_verifier.source=workflow_source",
        "workflow_verifier.scratch=workflow_scratch",
        "workflow_verifier.control=workflow_control",
    ].joined(separator: " ")
    configuration.bootLoader = bootLoader

    let disk = try VZDiskImageStorageDeviceAttachment(
        url: try regularFile(request.image.rootfsPath, context: "rootfs"),
        readOnly: true
    )
    configuration.storageDevices = [VZVirtioBlockDeviceConfiguration(attachment: disk)]
    configuration.directorySharingDevices = [
        try directoryShare(tag: "workflow_source", path: request.sourceRoot, readOnly: true),
        try directoryShare(tag: "workflow_scratch", path: request.scratchRoot, readOnly: false),
        try directoryShare(tag: "workflow_control", path: request.controlRoot, readOnly: false),
    ]
    configuration.networkDevices = []
    configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]

    let consoleUrl = URL(fileURLWithPath: request.controlRoot)
        .appendingPathComponent("console.log", isDirectory: false)
    FileManager.default.createFile(atPath: consoleUrl.path, contents: nil)
    let console = try FileHandle(forWritingTo: consoleUrl)
    let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
    serial.attachment = VZFileHandleSerialPortAttachment(
        fileHandleForReading: FileHandle.nullDevice,
        fileHandleForWriting: console
    )
    configuration.serialPorts = [serial]
    try configuration.validate()
    return configuration
}

@available(macOS 13.0, *)
private final class VmDelegate: NSObject, VZVirtualMachineDelegate {
    let stopped = DispatchSemaphore(value: 0)
    var failure: Error?

    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        stopped.signal()
    }

    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        failure = error
        stopped.signal()
    }
}

@available(macOS 13.0, *)
private func runVirtualMachine(_ configuration: VZVirtualMachineConfiguration, timeout: UInt64) throws {
    let queue = DispatchQueue(label: "dev.workflow-verifier.vm")
    let machine = VZVirtualMachine(configuration: configuration, queue: queue)
    let delegate = VmDelegate()
    machine.delegate = delegate
    let started = DispatchSemaphore(value: 0)
    var startFailure: Error?
    queue.async {
        machine.start { result in
            if case .failure(let error) = result { startFailure = error }
            started.signal()
        }
    }
    guard started.wait(timeout: .now() + 30) == .success else {
        try fail("VM start timed out")
    }
    if let error = startFailure { throw error }
    let waitSeconds = min(timeout, UInt64(Int.max - 15)) + 15
    guard delegate.stopped.wait(timeout: .now() + .seconds(Int(waitSeconds))) == .success else {
        queue.async {
            if machine.canStop { machine.stop { _ in } }
        }
        try fail("VM guest did not stop after its execution deadline")
    }
    if let error = delegate.failure { throw error }
}

private func validatedObservation(at path: URL, limit: UInt64) throws -> Data {
    let url = try regularFile(path.path, context: "VM observation")
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    let size = (attributes[.size] as? NSNumber)?.uint64Value ?? UInt64.max
    let doubled = limit.multipliedReportingOverflow(by: 2)
    let framed = doubled.partialValue.addingReportingOverflow(64 * 1024)
    guard !doubled.overflow, !framed.overflow, size <= framed.partialValue else {
        try fail("VM observation exceeds its framing limit")
    }
    let data = try Data(contentsOf: url)
    let root = try JSONSerialization.jsonObject(with: data)
    guard let object = root as? [String: Any] else { try fail("VM observation must be an object") }
    try validateExactKeys(
        object,
        expected: ["code", "output_exceeded", "output_hex", "schema", "timed_out"],
        context: "VM observation"
    )
    guard object["schema"] as? String == observationSchema,
          let output = object["output_hex"] as? String,
          output.count % 2 == 0,
          output.utf8.allSatisfy({ $0.isHexDigit }) else {
        try fail("invalid vm-observation-v1 response")
    }
    return data
}

private extension UInt8 {
    var isHexDigit: Bool {
        (48...57).contains(self) || (65...70).contains(self) || (97...102).contains(self)
    }
}

@main
private struct WorkflowVerifierVm {
    static func main() {
        do {
            guard #available(macOS 13.0, *) else {
                try fail("Virtualization.framework requires macOS 13 or newer")
            }
            guard VZVirtualMachine.isSupported else { try fail("hardware virtualization is unavailable") }
            let arguments = Array(CommandLine.arguments.dropFirst())
            guard arguments.count == 2, ["--probe", "--run"].contains(arguments[0]) else {
                try fail("usage: workflow-verifier-vm-shim --probe|--run REQUEST.json")
            }
            let (request, _) = try decodeRequest(arguments[1])
            let vmConfiguration = try configuration(for: request)
            if arguments[0] == "--probe" {
                FileHandle.standardOutput.write(
                    Data("{\"available\":true,\"schema\":\"vm-shim-probe-v1\"}\n".utf8)
                )
                return
            }
            try runVirtualMachine(vmConfiguration, timeout: request.timeoutSeconds)
            let response = try validatedObservation(
                at: URL(fileURLWithPath: request.controlRoot)
                    .appendingPathComponent("response.json", isDirectory: false),
                limit: request.outputBytes
            )
            FileHandle.standardOutput.write(response)
        } catch {
            FileHandle.standardError.write(Data("VM shim failure: \(error.localizedDescription)\n".utf8))
            exit(5)
        }
    }
}
