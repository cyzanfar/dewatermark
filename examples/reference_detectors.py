"""Exercise deterministic research fixtures without a model or network."""

from dewatermark import (
    doctor_detectors,
    generate_reference_text,
    inspect,
    run_reference_conformance,
)

fixture = generate_reference_text("kgw-word-v1", token_count=96, seed=11)
evidence = inspect(fixture, detector="reference-kgw")

print(evidence.to_dict())
print(run_reference_conformance().to_dict())
print(doctor_detectors().to_dict())
