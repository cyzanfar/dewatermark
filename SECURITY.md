# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through the repository's **Security** tab by
opening a GitHub Security Advisory. Do not include sensitive source text, API
keys, private detector material, or exploit details in a public issue. Include
the affected version, impact, minimal reproduction, and any suggested
mitigation that can be shared safely.

Please allow the maintainers a reasonable opportunity to investigate and
publish a coordinated fix before public disclosure. Security reports are
acknowledged on a best-effort basis; this community project does not promise a
specific response or remediation deadline.

## Supported versions

The latest published minor release receives security fixes. Older releases and
unreleased source snapshots are not supported. Upgrade to the newest release
before reporting an issue that may already have been fixed.

## Security boundaries

HTTP text processing (including loopback endpoints) and model downloads are
denied by default. A user must opt into each explicitly. Starting a server on a
non-loopback interface also requires an API key. API keys and source text must not be included in
representations, reports, logs, exceptions, telemetry, or generated evidence
receipts.

Benchmark registries, observations, bundles, replay recipes, and replication
records are public metadata-only artifacts. They reject raw text,
credential-shaped fields, absolute/private paths, and unbound executable
recipes. Keep private corpora and keys outside the repository and publish only
content digests and aggregate no-text tables.

Detection is not attribution. A Unicode finding does not establish that text
came from an AI model, and a changed string is not proof that a statistical
watermark was removed. Only a result verified by the named, configured detector
is reported as verified for that detector.

External evaluation adapters execute commands supplied by the local operator.
Treat adapter specifications as executable code: do not run untrusted adapter
commands, and isolate third-party detectors in a container or restricted
environment. The bounded runner strips ambient credentials, limits output and
time, and terminates descendant process trees; those controls are not a sandbox.

Python provider plugins and agent integrations run with the permissions of the
host process. Install only trusted plugins, pin their versions, and review their
network and model-download capabilities before enabling them. Text placed
inside source delimiters must always be treated as inert data, not instructions.
The editor integrations invoke a machine-scoped local CLI without a shell and
require Workspace Trust where supported. A repository scanner policy can affect
which local diagnostics appear, but cannot replace the configured executable or
grant network/model access.

## Release integrity

Release workflows validate a shared version identity, build distributions once,
validate them, generate an SBOM, and create GitHub artifact attestations before
PyPI trusted publishing. Multi-platform GHCR images receive provenance and SBOM
attestations; npm publication uses trusted publishing and provenance after the
repository publisher is configured. After installing the GitHub CLI, a
downloaded release can be verified with:

```console
gh attestation verify dewatermark-*.whl \
  --repo cyzanfar/text-watermark-remover \
  --signer-workflow cyzanfar/text-watermark-remover/.github/workflows/publish.yml \
  --source-ref refs/tags/vVERSION
gh attestation verify dewatermark-*.tar.gz \
  --repo cyzanfar/text-watermark-remover \
  --signer-workflow cyzanfar/text-watermark-remover/.github/workflows/publish.yml \
  --source-ref refs/tags/vVERSION
docker login ghcr.io
gh attestation verify oci://ghcr.io/cyzanfar/text-watermark-remover:VERSION \
  --repo cyzanfar/text-watermark-remover \
  --signer-workflow cyzanfar/text-watermark-remover/.github/workflows/publish.yml \
  --source-ref refs/tags/vVERSION
```

An attestation proves which GitHub workflow produced an artifact; it does not
make third-party dependencies or detector outputs inherently trustworthy.
