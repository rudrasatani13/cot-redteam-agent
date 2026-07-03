"""
Anthropic model adapter.
"""
from __future__ import annotations
from typing import Any, Dict, Optional, AsyncGenerator
import httpx
import asyncio
from cot_redteam.models.base import BaseModel, ModelRegistry
from cot_redteam.core.types import ModelConfig, ModelProvider, ModelResponse


@ModelRegistry.register(ModelProvider.ANTHROPIC.value)
class AnthropicModel(BaseModel):
    """Anthropic API adapter."""
    
    def __init__(self, config: ModelConfig):
        super().__init__(config)
        self.api_key = config.api_key or config.extra_params.get("api_key")
        self.base_url = config.base_url or "https://api.anthropic.com"
        self.timeout = config.timeout
        self.max_retries = config.max_retries
        self._client: Optional[httpx.AsyncClient] = None
        self.api_version = "2023-06-01"
    
    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            headers = {
                "x-api-key": self.api_key,
                "Content-Type": "application/json",
                "anthropic-version": self.api_version,
            }
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=headers,
                timeout=self.timeout,
            )
        return self._client
    
    def generate(
        self, 
        prompt: str, 
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> str:
        return asyncio.run(self.agenerate(prompt, temperature, max_tokens, **kwargs))
    
    async def agenerate(
        self, 
        prompt: str, 
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> str:
        client = await self._get_client()
        
        payload = {
            "model": self.config.model_id,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": max_tokens if max_tokens is not None else self.config.max_tokens,
            **kwargs,
        }
        
        for attempt in range(self.max_retries):
            try:
                resp = await client.post("/v1/messages", json=payload)
                resp.raise_for_status()
                data = resp.json()
                return data["content"][0]["text"]
            except httpx.HTTPStatusError as e:
                if e.response.status_code >= 500 and attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise
            except Exception as e:
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise
        
        raise RuntimeError("Max retries exceeded")
    
    async def stream(
        self, 
        prompt: str, 
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> AsyncGenerator[str, None]:
        client = await self._get_client()
        
        payload = {
            "model": self.config.model_id,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": max_tokens if max_tokens is not None else self.config.max_tokens,
            "stream": True,
            **kwargs,
        }
        
        async with client.stream("POST", "/v1/messages", json=payload) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if line.startswith("data: "):
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        break
                    try:
                        import json
                        data = json.loads(data_str)
                        if data.get("type") == "content_block_delta":
                            yield data["delta"]["text"]
                    except Exception:
                        continue
    
    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None


ModelRegistry.register("anthropic")(AnthropicModel)