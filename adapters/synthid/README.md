# SynthID Text integration template

This is a fail-closed manifest template for the official reference repository
at `google-deepmind/synthid-text@addb4a158143c7c6851a1308f78b89fceed59683`
(Apache-2.0). The relevant source-file digests are pinned so an operator can
build an isolated command adapter without silently following `main`.

It is not a detector implementation, a completed replication, or support for
Gemini production watermarks. The official reference uses configuration keys,
tokenization, masking, and length-sensitive detection/calibration inputs. Every
`null` field must be resolved, public configuration must be fingerprinted, and
independent golden-vector plus matched-control evidence must pass before an
adapter can be registered as calibrated. Gemini production keys are not public.
