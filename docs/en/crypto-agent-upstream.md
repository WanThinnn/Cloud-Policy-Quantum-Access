# Prepare the Crypto Agent native library

Run these commands from the CPQA repository root with Python 3.10 or newer.
Windows and Linux use x86-64 packages. macOS supports both Intel and Apple silicon.
Run the tool in a native shell for the architecture you intend to package.

```sh
# Download the latest published release
python src/crypto_agent/prepare_upstream.py

# Pin a release for reproducible packaging
python src/crypto_agent/prepare_upstream.py --ref v6.0.0 --output-dir src/crypto_agent/target/upstream/pinned

# Build the original upstream source using its Makefile and SDK packager
python src/crypto_agent/prepare_upstream.py --source source --ref v6.0.0 --jobs 4 --output-dir src/crypto_agent/target/upstream/from-source
```

Without `--ref`, a source build fetches the upstream default branch. Use a Git
commit when an exact source revision is required. Source builds require the tools
listed in the upstream README. On Windows, run from an x64 Native Tools prompt
with GNU Make and the upstream dependencies available. The release path verifies
the archive against the SHA-256 digest in GitHub release metadata before unpacking.
Pin releases for controlled rollout and retain the recorded hash.

The default output is `src/crypto_agent/target/upstream/<platform>-<arch>`.
The output directory must be new. The bundle contains the platform shared library,
`libcpabe_tkn20.dll` on Windows, upstream redistribution notices, and
`upstream-manifest.json`. The manifest records the release tag or resolved Git
commit, archive SHA-256, platform, and individual runtime library hashes. Keep
the runtime libraries beside the agent executable as required by the FFI loader.
Windows also requires the MSVC runtime. This command prepares the library bundle.
Browser registration and installation of the agent executable are separate steps.

[Upstream source and build requirements](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library)
· [Release v6.0.0](https://github.com/WanThinnn/Hybrid-PQ-CP-ABE-Library/releases/tag/v6.0.0)
