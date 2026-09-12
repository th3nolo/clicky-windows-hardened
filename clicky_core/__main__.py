"""Start the worker with an explicitly selected, real Clicky inference provider."""

import argparse
import asyncio
import sys
from typing import Annotated

from pydantic import Field

from clicky_core.commands import StrictModel
from clicky_core.worker import run


class Settings(StrictModel):
    provider: str
    model: Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")]


def main() -> None:
    from ai.provider_catalog import OPENAI_COMPATIBLE_SPECS
    from ai.provider_factory import create_llm_provider
    from clicky_core.provider import ClickyProvider

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--provider",
        required=True,
        choices=[
            "openai",
            "claude",
            "gemini",
            "lmstudio",
            "ollama",
            *OPENAI_COMPATIBLE_SPECS,
        ],
    )
    parser.add_argument("--model", required=True)
    settings = Settings.model_validate(vars(parser.parse_args()))
    try:
        provider = ClickyProvider(
            settings.provider, settings.model, create_llm_provider(settings.provider)
        )
        asyncio.run(run(provider))
    except (BrokenPipeError, KeyboardInterrupt):
        pass
    except Exception:
        # Provider exceptions can contain endpoint or credential details.
        print(
            "Worker failed; check provider configuration and installed dependencies.",
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
