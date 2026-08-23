import gzip
import json
from pathlib import Path
import struct
import tempfile
import unittest

from scripts.build_vm_bundle import build_bundle, read_newc


def elf_agent(architecture: str, *, interpreter: bool = False) -> bytes:
    machine = {"x86_64": 62, "arm64": 183}[architecture]
    image = bytearray(64 + 56)
    image[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into(
        "<HHIQQQIHHHHHH",
        image,
        16,
        2,
        machine,
        1,
        0,
        64,
        0,
        0,
        64,
        56,
        1,
        0,
        0,
        0,
    )
    struct.pack_into("<IIQQQQQQ", image, 64, 3 if interpreter else 1, 5, 0, 0, 0, 0, 0, 0)
    return bytes(image)


def ext4_rootfs() -> bytes:
    image = bytearray(2048)
    image[1080:1082] = b"\x53\xef"
    return bytes(image)


class BuildVmBundleTests(unittest.TestCase):
    def test_bundle_is_deterministic_and_embeds_the_exact_agent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            kernel = root / "kernel"
            rootfs = root / "rootfs"
            agent = root / "agent"
            kernel.write_bytes(b"kernel-image")
            rootfs.write_bytes(ext4_rootfs())
            agent.write_bytes(elf_agent("arm64"))
            first = root / "first"
            second = root / "second"
            build_bundle(kernel, rootfs, agent, first, "arm64", "test.1")
            build_bundle(kernel, rootfs, agent, second, "arm64", "test.1")

            self.assertEqual(
                (first / "manifest.json").read_bytes(),
                (second / "manifest.json").read_bytes(),
            )
            self.assertEqual(
                (first / "initrd.img").read_bytes(),
                (second / "initrd.img").read_bytes(),
            )
            manifest = json.loads((first / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema"], "vm-image-v1")
            archive = gzip.decompress((first / "initrd.img").read_bytes())
            files = read_newc(archive)
            self.assertEqual(files["workflow-verifier-vm-agent"], elf_agent("arm64"))
            self.assertIn("dev", files)
            self.assertEqual((first / "workflow-verifier-vm-agent").read_bytes(), agent.read_bytes())

    def test_builder_rejects_symlinks_and_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            kernel = root / "kernel"
            rootfs = root / "rootfs"
            agent = root / "agent"
            kernel.write_bytes(b"kernel")
            rootfs.write_bytes(ext4_rootfs())
            agent.write_bytes(elf_agent("x86_64"))
            output = root / "bundle"
            output.mkdir()
            with self.assertRaises(ValueError):
                build_bundle(kernel, rootfs, agent, output, "x86_64", "test")
            if hasattr(Path, "symlink_to"):
                linked = root / "linked-kernel"
                try:
                    linked.symlink_to(kernel)
                except OSError:
                    return
                with self.assertRaises(ValueError):
                    build_bundle(linked, rootfs, agent, root / "other", "x86_64", "test")

    def test_manifest_uses_the_protocol_canonical_utf8_encoding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            kernel = root / "kernel"
            rootfs = root / "rootfs"
            agent = root / "agent"
            kernel.write_bytes(b"kernel")
            rootfs.write_bytes(ext4_rootfs())
            agent.write_bytes(elf_agent("arm64"))
            output = root / "bundle"

            build_bundle(kernel, rootfs, agent, output, "arm64", "release-日本")

            manifest = (output / "manifest.json").read_bytes()
            self.assertIn("日本".encode("utf-8"), manifest)
            self.assertNotIn(b"\\u65e5", manifest)

    def test_builder_rejects_non_ext4_dynamic_or_wrong_architecture_agent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            kernel = root / "kernel"
            rootfs = root / "rootfs"
            agent = root / "agent"
            kernel.write_bytes(b"kernel")

            rootfs.write_bytes(b"not-ext4")
            agent.write_bytes(elf_agent("arm64"))
            with self.assertRaisesRegex(ValueError, "ext4"):
                build_bundle(kernel, rootfs, agent, root / "bad-rootfs", "arm64", "test")

            rootfs.write_bytes(ext4_rootfs())
            agent.write_bytes(elf_agent("x86_64"))
            with self.assertRaisesRegex(ValueError, "architecture"):
                build_bundle(kernel, rootfs, agent, root / "wrong-arch", "arm64", "test")

            agent.write_bytes(elf_agent("arm64", interpreter=True))
            with self.assertRaisesRegex(ValueError, "static"):
                build_bundle(kernel, rootfs, agent, root / "dynamic", "arm64", "test")


if __name__ == "__main__":
    unittest.main()
