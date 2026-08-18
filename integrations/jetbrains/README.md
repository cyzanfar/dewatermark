# Dewatermark JetBrains inspection

This proof-of-concept IntelliJ Platform plugin maps the local
`dewatermark check` report to editor inspection highlights. Its quick fix runs
the safe Unicode policy only after the user selects it. The bridge uses an argv
process boundary without a shell, a minimal credential-free environment,
bounded output, and a deadline; it never opens a socket.

Requirements: a Java runtime able to launch Gradle and
`dewatermark>=0.6,<0.7` on the IDE process PATH. The checksum-pinned wrapper
provisions the Java 21 compile toolchain when it is not installed locally.

Install the matching CLI with `pipx install 'dewatermark>=0.6,<0.7'`.

```bash
cd integrations/jetbrains
./gradlew --dependency-verification=strict test buildPlugin verifyPlugin
```

The verifier target set is pinned to four IDEA releases from 2025.2 through
2026.2 instead of following the changing `recommended()` channel. Gradle
checksums cover the supported Linux, macOS, and Windows installer variants;
update them only after checking the corresponding checksum published by
JetBrains.

Install the ZIP from `build/distributions` through the IDE's “Install Plugin
from Disk” action. This remains a local Unicode inspection; it does not infer
authorship or claim support for undisclosed statistical watermarks.

The plugin labels stdin with the local file path and starts the CLI in the
file's directory, so the nearest `.dewatermark.toml` or
`[tool.dewatermark.scan]` policy applies to unsaved editor buffers.
