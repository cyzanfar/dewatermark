# Compatibility policy

The project uses Semantic Versioning. Public names exported from
`dewatermark.__all__`, CLI subcommands, provider protocols, exit codes, and
schema-major `1` fields are stable for the 0.3 line. Experimental mechanism
internals and `eval` implementation details are not stable.

Deprecations remain available for at least one minor release. The unprefixed
v0.2 environment variables remain aliases during 0.3; new integrations should
use `DEWATERMARK_*` names. Python versions are supported from 3.9 through the
latest version validated in CI.

Provider protocol additions will be optional within a minor release. Required
method changes or removal of result fields require a major release.
