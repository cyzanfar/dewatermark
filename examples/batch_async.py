"""Ordered batch processing and asynchronous integration."""

import asyncio

from dewatermark import DewatermarkConfig, aremove, remove_many

CONFIG = DewatermarkConfig(local_lm_enabled=False)
items = remove_many(["a\u200bb", "c\u200bd"], mode="sanitize", config=CONFIG)
print([item.result.cleaned_text for item in items if item.succeeded])


async def main() -> None:
    result = await aremove("a\u200bb", mode="sanitize", config=CONFIG)
    print(result.to_dict())


asyncio.run(main())
