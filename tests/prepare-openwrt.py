#!/usr/bin/env python3
"""Prepare native OpenWrt userspace for tests; no emulator or VM is started."""
import gzip
import hashlib
import io
import platform
from pathlib import Path
import ssl
import tarfile
import urllib.request

cache = Path(__file__).resolve().parents[1] / "windows/dist/router-tests"
cache.mkdir(parents=True, exist_ok=True)
root = cache / "rootfs"
arch = platform.machine()
if arch in ("x86_64", "amd64"):
    target, package_arch = "x86/64", "x86_64"
    image = "openwrt-24.10.4-x86-64-rootfs.tar.gz"
elif arch in ("aarch64", "arm64"):
    target, package_arch = "armsr/armv8", "aarch64_generic"
    image = "openwrt-24.10.4-armsr-armv8-rootfs.tar.gz"
else:
    raise SystemExit("Native OpenWrt test architecture unsupported")
context = ssl.create_default_context()
def get(url):
    with urllib.request.urlopen(url, timeout=90, context=context) as response:
        return response.read()
base = f"https://downloads.openwrt.org/releases/24.10.4/targets/{target}/"
checksums = get(base + "sha256sums").decode()
expected = next(line.split()[0] for line in checksums.splitlines() if line.split()[-1].lstrip("*") == image)
archive = cache / image
if not archive.exists():
    archive.write_bytes(get(base + image))
if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
    raise SystemExit("OpenWrt rootfs checksum mismatch")
root.mkdir(exist_ok=True)
with tarfile.open(archive) as source:
    # Distribution rootfs has absolute symlinks by design. Extract only the
    # verified OpenWrt archive into its own disposable root directory.
    source.extractall(root, filter="fully_trusted")
feed = f"https://downloads.openwrt.org/releases/24.10.4/packages/{package_arch}/base/"
index = gzip.decompress(get(feed + "Packages.gz")).decode()
record = next(block for block in index.split("\n\n") if block.startswith("Package: ucode-mod-socket\n"))
fields = dict(line.split(": ", 1) for line in record.splitlines() if ": " in line and not line.startswith(" "))
package = get(feed + fields["Filename"])
if hashlib.sha256(package).hexdigest() != fields["SHA256sum"]:
    raise SystemExit("OpenWrt socket module checksum mismatch")
if package.startswith(b"!<arch>\n"):
    offset, payload = 8, None
    while offset + 60 <= len(package):
        header = package[offset:offset + 60]
        name, size = header[:16].decode().strip().rstrip("/"), int(header[48:58])
        offset += 60
        if name.startswith("data.tar"):
            payload = package[offset:offset + size]
            break
        offset += size + size % 2
    if payload is None:
        raise SystemExit("Module archive has no payload")
else:
    with tarfile.open(fileobj=io.BytesIO(package)) as outer:
        member = next(m for m in outer.getmembers() if m.name.lstrip("./").startswith("data.tar"))
        payload = outer.extractfile(member).read()
with tarfile.open(fileobj=io.BytesIO(payload)) as source:
    source.extractall(root, filter="fully_trusted")
print(root)
