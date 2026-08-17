# Extensions

Implement the structural protocols in `dewatermark.protocols`. A rewriter needs
`available()` and `rewrite(text, **options) -> (text, details)`. A scorer needs
`available()`, `self_information(text)`, and `score(text)`.

Register an in-process provider:

```python
from dewatermark import DewatermarkConfig, register_provider, remove

register_provider("example", lambda config: ExampleRewriter(config))
config = DewatermarkConfig(rewriter_provider="example")
result = remove("source text", config=config)
```

Distributions can publish providers through the `dewatermark.providers` entry
point group:

```toml
[project.entry-points."dewatermark.providers"]
example = "example_package:factory"
```

Factories receive `DewatermarkConfig`. They must honor privacy policy, avoid
logging source text or secrets, return JSON-compatible details, and expose
deterministic mocked contract tests. Name collisions are rejected.
