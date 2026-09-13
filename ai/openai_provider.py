from typing import AsyncGenerator, List

from ai.base_provider import BaseLLMProvider, Message
from ai.sdk_isolation import create_openai_client
from config import cfg

DEFAULT_MODEL = "gpt-4o"
MAX_TOKENS = 1024


class OpenAIProvider(BaseLLMProvider):

    def __init__(self):
        # Keep explicitly configured compatible routers; SDK environment alone
        # must not redirect this provider or add another provider's headers.
        self._client = create_openai_client(
            api_key=cfg.openai_api_key,
            base_url=cfg.openai_base_url or "https://api.openai.com/v1",
            timeout=600.0, max_retries=2,
        )

    async def stream_response(
        self,
        user_text: str,
        screenshots_b64: List[str],
        history: List[Message],
        system_prompt: str,
        model: str | None = None,
    ) -> AsyncGenerator[str, None]:
        model = model or cfg.openai_default_model or DEFAULT_MODEL

        messages = [{"role": "system", "content": system_prompt}]

        for msg in history:
            messages.append({"role": msg.role, "content": msg.content})

        content: list = []
        for img_b64 in screenshots_b64:
            content.append({
                "type": "image_url",
                "image_url": {"url": f"data:image/jpeg;base64,{img_b64}", "detail": "high"},
            })
        content.append({"type": "text", "text": user_text})
        messages.append({"role": "user", "content": content})

        stream = await self._client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=MAX_TOKENS,
            stream=True,
        )
        try:
            async for chunk in stream:
                delta = chunk.choices[0].delta
                if delta.content:
                    yield delta.content
        finally:
            await stream.close()

    async def health_check(self) -> bool:
        try:
            await self._client.models.list()
            return True
        except Exception:
            return False
