"""Allow ``python -m dewatermark`` wherever console scripts are unavailable."""

from .cli import main

raise SystemExit(main())
