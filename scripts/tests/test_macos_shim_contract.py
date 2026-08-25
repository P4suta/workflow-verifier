import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SHIM = ROOT / "helpers" / "macos" / "shim" / "WorkflowVerifierVm.swift"
ENTITLEMENTS = ROOT / "helpers" / "macos" / "shim" / "WorkflowVerifierVm.entitlements"
BUILD = ROOT / "helpers" / "macos" / "build-shim.sh"


class MacOsShimContract(unittest.TestCase):
    def test_virtualization_boundary_is_explicit_and_networkless(self) -> None:
        source = SHIM.read_text(encoding="utf-8")
        for required in (
            "configuration.networkDevices = []",
            "VZLinuxBootLoader",
            "VZDiskImageStorageDeviceAttachment",
            "readOnly: true",
            'directoryShare(tag: "workflow_source"',
            'directoryShare(tag: "workflow_scratch"',
            'directoryShare(tag: "workflow_control"',
            "try configuration.validate()",
        ):
            self.assertIn(required, source)

    def test_shim_revalidates_protocol_shape_and_every_image_digest(self) -> None:
        source = SHIM.read_text(encoding="utf-8")
        for required in (
            "import CryptoKit",
            "vm-shim-request-v1",
            "vm-observation-v1",
            "validateExactKeys",
            "verifyDigest(request.image.kernelPath",
            "verifyDigest(request.image.initrdPath",
            "verifyDigest(request.image.rootfsPath",
            "manifestDigest",
        ):
            self.assertIn(required, source)

    def test_shim_has_only_the_virtualization_entitlement(self) -> None:
        value = ENTITLEMENTS.read_text(encoding="utf-8")
        self.assertIn("com.apple.security.virtualization", value)
        self.assertNotIn("com.apple.security.network.client", value)
        self.assertNotIn("com.apple.security.network.server", value)

    def test_ad_hoc_build_has_fixed_identity_and_no_timestamp(self) -> None:
        source = BUILD.read_text(encoding="utf-8")
        self.assertIn("--timestamp=none", source)
        self.assertIn("--identifier dev.workflow-verifier.vm-shim", source)
        self.assertIn("WORKFLOW_VERIFIER_CODESIGN_IDENTITY:--", source)


if __name__ == "__main__":
    unittest.main()
