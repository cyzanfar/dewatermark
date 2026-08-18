# Dewatermark VS Code extension

This proof-of-concept renders local `dewatermark check` results as editor
diagnostics and offers an explicit safe-profile cleanup quick fix. It invokes
the configured executable with `shell: false`, passes document text only on
stdin, strips ambient credentials from the child environment, caps output, and
never opens a socket.

This bridge requires `dewatermark>=0.6,<0.7` because it uses the policy-aware
`check --stdin-path` contract. Until `v0.6.0` is published, install the release
candidate from the repository root; after release, use the stable constraint:

```bash
pipx install --force .
# After v0.6.0 is published: pipx install 'dewatermark>=0.6,<0.7'
cd integrations/vscode
npm ci
npm test
npm run package
```

Settings allow changing the local executable, enabling scan-on-change, and
showing contextual observations. Cleanup is never automatic: use the quick fix
or `Dewatermark: Apply Safe Unicode Cleanup` command.

The executable setting is machine-scoped so a repository cannot replace it
through workspace settings, and the extension stays disabled until an
untrusted workspace is explicitly trusted. Superseded scans are cancelled,
input and output are bounded, and code-point positions are translated to VS
Code's UTF-16 editor coordinates.

Each in-memory buffer is labelled with its local file path and the CLI runs in
that file's directory. The nearest `.dewatermark.toml` or
`[tool.dewatermark.scan]` policy therefore controls exclusions, extensions,
dispositions, and suppressions even before the buffer is saved.

This integration handles literal Unicode artifacts. It does not label text as
AI-authored and does not claim to detect statistical or private vendor marks.
