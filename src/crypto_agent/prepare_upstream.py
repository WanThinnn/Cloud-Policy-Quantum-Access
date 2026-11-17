"""Prepare an isolated runtime bundle for the CPQA Crypto Agent."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.request import Request, urlopen
import zipfile


REPO = "WanThinnn/Hybrid-PQ-CP-ABE-Library"
GITHUB = f"https://github.com/{REPO}"
API = f"https://api.github.com/repos/{REPO}"
ROOT = Path(__file__).resolve().parent
LIBRARY = "libhybrid-pq-cp-abe"
TARGETS = {
    ("windows", "x86_64"): ("win", (f"{LIBRARY}.dll", "libcpabe_tkn20.dll")),
    ("linux", "x86_64"): ("linux", (f"{LIBRARY}.so",)),
    ("macos", "arm64"): ("macos", (f"{LIBRARY}.dylib",)),
    ("macos", "x86_64"): ("macos", (f"{LIBRARY}.dylib",)),
}
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?")


def native_target():
    system = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}.get(platform.system())
    architecture = platform.machine().lower()
    arch = {"amd64": "x86_64", "aarch64": "arm64"}.get(architecture, architecture)
    if (system, arch) not in TARGETS:
        raise ValueError(f"No supported upstream build for {platform.system()} {architecture}.")
    return system, arch


def open_url(url):
    return urlopen(Request(url, headers={"User-Agent": "CPQA-Crypto-Agent"}), timeout=60)


def sha256(path):
    with path.open("rb") as source:
        digest = hashlib.sha256()
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
        return digest.hexdigest()


def release_archive(work, label, arch, requested_tag):
    endpoint = f"tags/{requested_tag}" if requested_tag else "latest"
    with open_url(f"{API}/releases/{endpoint}") as response:
        release = json.load(response)
    tag = release["tag_name"]
    if not TAG.fullmatch(tag) or (requested_tag and tag != requested_tag):
        raise ValueError("Unexpected upstream release tag.")
    name = f"{LIBRARY}_{label}_{arch}_{tag}.zip"
    assets = [asset for asset in release["assets"] if asset["name"] == name]
    if len(assets) != 1:
        raise ValueError(f"{tag} does not publish exactly one {name} asset.")
    asset = assets[0]
    digest = asset.get("digest") or ""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError(f"GitHub did not publish a SHA-256 digest for {name}.")
    url = f"{GITHUB}/releases/download/{tag}/{name}"
    if asset["browser_download_url"] != url:
        raise ValueError("Unexpected upstream release asset URL.")
    archive = work / name
    with open_url(url) as response, archive.open("xb") as output:
        shutil.copyfileobj(response, output)
    if archive.stat().st_size != asset["size"] or sha256(archive) != digest[7:]:
        raise ValueError(f"Downloaded archive failed the integrity check for {name}.")
    return archive, {"source": "release", "tag": tag, "url": url, "archive_sha256": digest[7:]}


def source_archive(checkout, system, label, arch, ref, jobs):
    env = {**os.environ, "GIT_LFS_SKIP_SMUDGE": "1"}

    def run(*command):
        subprocess.run(command, cwd=checkout, env=env, check=True)

    run("git", "init", "--quiet")
    if system == "windows":
        run("git", "config", "--local", "core.longpaths", "true")
    run("git", "fetch", "--quiet", "--depth=1", f"{GITHUB}.git", ref)
    run("git", "checkout", "--quiet", "--detach", "FETCH_HEAD")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip()
    run("make", f"-j{jobs}", "deps")
    run("make", f"-j{jobs}")
    package_version = f"dev-{commit[:12]}"
    run(sys.executable, "scripts/package-release.py", "--platform", system, "--arch", arch,
        "--version", package_version)
    archive = checkout / "build" / "release" / f"{LIBRARY}_{label}_{arch}_v{package_version}.zip"
    return archive, {
        "source": "source", "ref": ref, "commit": commit,
        "url": f"{GITHUB}/tree/{commit}", "archive_sha256": sha256(archive),
    }


def stage_runtime(archive, staging, libraries):
    root = archive.stem
    with zipfile.ZipFile(archive) as package:
        for library in libraries:
            with package.open(f"{root}/lib/{library}") as source, (staging / library).open("xb") as output:
                shutil.copyfileobj(source, output)
            if not (staging / library).stat().st_size:
                raise ValueError(f"Empty runtime library: {library}.")
        for member in package.infolist():
            parts = PurePosixPath(member.filename).parts
            if member.is_dir() or len(parts) < 2 or parts[0] != root:
                continue
            relative = parts[1:]
            if relative[0] not in {"LICENSE", "NOTICE", "VERSION", "licenses", "vendor"}:
                continue
            if any(not part or part in {".", ".."} or re.search(r'[\\:*?"<>|]', part) for part in relative):
                raise ValueError(f"Invalid notice path in {archive.name}.")
            destination = staging.joinpath(*relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with package.open(member) as source, destination.open("xb") as output:
                shutil.copyfileobj(source, output)
    return {name: sha256(staging / name) for name in libraries}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=("release", "source"), default="release")
    parser.add_argument("--ref", help="Release tag, or upstream Git ref when building from source.")
    parser.add_argument("--jobs", type=int, default=4, help="Parallel Make jobs for source builds.")
    parser.add_argument("--output-dir", type=Path, help="New directory for the staged runtime bundle.")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive.")
    if args.ref:
        if args.source == "release" and not TAG.fullmatch(args.ref):
            parser.error("--ref must be a release tag such as v6.0.0.")
        if args.source == "source" and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", args.ref):
            parser.error("--ref must be a Git branch, tag, or commit.")
    try:
        system, arch = native_target()
        label, libraries = TARGETS[system, arch]
        output = (args.output_dir or ROOT / "target" / "upstream" / f"{system}-{arch}").absolute()
        if output.exists():
            raise FileExistsError(f"{output} already exists. Use --output-dir for a fresh bundle.")
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=".cpqa-upstream-", dir=output.parent) as directory:
            work = Path(directory)
            staging = work / "runtime"
            staging.mkdir()
            if args.source == "release":
                archive, metadata = release_archive(work, label, arch, args.ref)
                runtime_hashes = stage_runtime(archive, staging, libraries)
            else:
                # Windows compilers and vendored dependencies need a short checkout path.
                with tempfile.TemporaryDirectory(prefix="cpqa-abe-") as source:
                    archive, metadata = source_archive(Path(source), system, label, arch, args.ref or "HEAD", args.jobs)
                    runtime_hashes = stage_runtime(archive, staging, libraries)
            metadata.update(revision=1, repository=REPO, platform=system, arch=arch, libraries=runtime_hashes)
            (staging / "upstream-manifest.json").write_text(
                json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8",
            )
            staging.rename(output)
        print(output)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        parser.exit(1, f"Upstream preparation failed: {error}\n")


if __name__ == "__main__":
    main()
