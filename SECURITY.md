# Security policy

Report vulnerabilities privately through GitHub Security Advisories for the
repository. Do not include sensitive source text, API keys, or proprietary
detector material in a public issue.

The latest minor release is supported. Remote text processing and model
downloads are denied by default. A user must opt into either explicitly. API
keys are redacted from configuration representations and serializers.

External evaluation adapters execute commands supplied by the local operator.
Treat adapter specifications as executable code: do not run untrusted adapter
commands, and isolate third-party detectors in a container or restricted
environment.
