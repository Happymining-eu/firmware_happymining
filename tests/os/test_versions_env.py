"""os/versions.env: pinned base release, no invented hash, sane policy values."""

from __future__ import annotations

import re

from hm_os_testlib import OS_DIR


def test_base_release_is_a_single_switch(versions):
    assert versions["UBUNTU_RELEASE"] in versions["SUPPORTED_UBUNTU_VERSIONS"].split()
    assert versions["UBUNTU_POINT_RELEASE"].startswith(versions["UBUNTU_RELEASE"])
    assert versions["UBUNTU_ISO_FILENAME"] == f"ubuntu-{versions['UBUNTU_POINT_RELEASE']}-live-server-amd64.iso"
    assert versions["UBUNTU_RELEASE_URL"] == f"https://releases.ubuntu.com/{versions['UBUNTU_RELEASE']}"
    assert versions["UBUNTU_SUMS_URL"] == versions["UBUNTU_RELEASE_URL"] + "/SHA256SUMS"
    assert versions["UBUNTU_SUMS_SIG_URL"] == versions["UBUNTU_RELEASE_URL"] + "/SHA256SUMS.gpg"
    # The release appears literally only once in the file: on the UBUNTU_RELEASE line.
    text = (OS_DIR / "versions.env").read_text()
    assignments = [ln for ln in text.splitlines() if ln and not ln.startswith("#")]
    literal = [ln for ln in assignments if re.search(r"https?://[^\s\"]*\b2[0-9]\.04\b", ln)]
    assert literal == [], "URLs must be derived from UBUNTU_RELEASE"


def test_no_iso_hash_is_pinned():
    text = (OS_DIR / "versions.env").read_text()
    assert not re.search(r"\b[0-9a-fA-F]{64}\b", text), "an ISO sha256 must never be stored; it comes from the signed SHA256SUMS"


def test_signing_key_fingerprint_and_sources(versions):
    assert re.fullmatch(r"[0-9A-F]{40}", versions["UBUNTU_CDIMAGE_KEY_FPR"])
    assert versions["UBUNTU_CDIMAGE_KEY_FPR"] == "843938DF228D22F7B3742BC0D94AA3F0EFE21092"
    text = (OS_DIR / "versions.env").read_text()
    for source in ("docs.vast.ai/host/verification-stages", "ubuntu.com/tutorials/how-to-verify-ubuntu",
                   "ubuntu.com/server/docs/how-to/graphics/install-nvidia-drivers", "console.vast.ai/install",
                   "releases.ubuntu.com"):
        assert source in text, f"missing source citation: {source}"


def test_agent_and_policy_values(versions):
    assert versions["AGENT_PACKAGE"] == "happymining-agent"
    assert versions["AGENT_DEB_FILENAME"] == "happymining-agent_0.1.0_amd64.deb"
    assert versions["NVIDIA_DRIVER_POLICY"] == "ubuntu-drivers-gpgpu"
    assert re.fullmatch(r"[0-9]+(\.[0-9]+)+", versions["NVIDIA_MIN_DRIVER_VERSION"])
    assert versions["VAST_DOCKER_DATA_FS"] == "xfs"
    assert versions["VAST_DOCKER_DATA_MOUNT"] == "/var/lib/docker"
    assert "pquota" in versions["VAST_DOCKER_DATA_MOUNT_OPTIONS"]
    assert int(versions["VAST_MIN_DOCKER_STORAGE_GB"]) == 200
