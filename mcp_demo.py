#!/usr/bin/env python3
"""
mcp_demo.py

Production-leaning MCP server 

- FastMCP-based MCP server (stdio) for Claude Desktop / MCP Inspector
- JWT authentication + scope-based RBAC for HTTP gateway
- Simple per-tenant+tool rate limiter
- OpenTelemetry tracing to console

Install deps:
    pip install mcp fastapi "uvicorn[standard]" pyjwt \
                opentelemetry-sdk opentelemetry-api
"""

import time
from functools import wraps
from typing import Any, Callable, Dict, Optional

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
import uvicorn

from mcp.server.fastmcp import FastMCP

# ------------------------------------------------------------------------------
# Observability (OpenTelemetry → console)
# ------------------------------------------------------------------------------

def setup_tracing(use_console: bool):
    provider = TracerProvider(
        resource=Resource.create({"service.name": "mcp-python-server"})
    )
    if use_console:
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    trace.set_tracer_provider(provider)
    return trace.get_tracer("mcp-python-server")


# ------------------------------------------------------------------------------
# Governance: scopes + rate-limit
# ------------------------------------------------------------------------------

_BUCKETS: dict[tuple[str, str], dict[str, float]] = {}


def rate_limit(calls: int, per_seconds: float):
    """Simple token-bucket rate limiter per (tenant, tool)."""

    def deco(fn: Callable):
        @wraps(fn)
        def wrapper(
            *args,
            tenant_id: str = "public",
            tool_name: str = "",
            **kwargs,
        ):
            key = (tenant_id, tool_name or fn.__name__)
            bucket = _BUCKETS.setdefault(
                key, {"tokens": calls, "ts": time.time()}
            )
            now = time.time()

            # Refill tokens
            bucket["tokens"] = min(
                calls,
                bucket["tokens"] + (now - bucket["ts"]) * (calls / per_seconds),
            )
            bucket["ts"] = now

            if bucket["tokens"] < 1:
                raise RuntimeError(f"Rate limit exceeded for {key}")

            bucket["tokens"] -= 1

            with tracer.start_as_current_span(
                f"rate_limit.{tool_name or fn.__name__}"
            ):
                return fn(*args, tenant_id=tenant_id, **kwargs)

        return wrapper

    return deco


def require_scopes(*needed: str):
    """
    Scope-based RBAC decorator.

    - If granted_scopes is None (stdio mode / trusted local host),
      we allow everything (no RBAC).
    - If granted_scopes is provided (HTTP gateway w/ JWT), we enforce it.
    """

    def deco(fn: Callable):
        @wraps(fn)
        def wrapper(
            *args,
            granted_scopes: Optional[list[str]] = None,
            **kwargs,
        ):
            if granted_scopes is None:
                # Local/stdio mode: skip RBAC
                return fn(*args, **kwargs)

            granted = set(granted_scopes)
            missing = [s for s in needed if s not in granted]
            if missing:
                raise PermissionError(f"Missing scopes: {missing}")
            return fn(*args, granted_scopes=granted_scopes, **kwargs)

        return wrapper

    return deco


# ------------------------------------------------------------------------------
# Auth: JWT helpers (used by HTTP gateway)
# ------------------------------------------------------------------------------

JWT_SECRET = "replace-me-in-prod"
JWT_ALG = "HS256"


def decode_jwt(token: str) -> Dict[str, Any]:
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])


def mint_demo_jwt(
    sub: str = "user-123",
    tenant: str = "acme",
    scopes: Optional[list[str]] = None,
) -> str:
    scopes = scopes or ["customer:read", "orders:search"]
    payload = {
        "sub": sub,
        "tenant": tenant,
        "scopes": scopes,
        "exp": int(time.time()) + 3600,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


# ------------------------------------------------------------------------------
# MCP server (FastMCP) – tools & resources
# ------------------------------------------------------------------------------

mcp = FastMCP("Python MCP Demo")

# Simple registry for HTTP gateway → names → functions
TOOLS: Dict[str, Callable[..., Any]] = {}


@mcp.tool()
@require_scopes("customer:read")
@rate_limit(calls=5, per_seconds=10)
def get_customer(
    customer_id: str,
    tenant_id: str = "public",
    granted_scopes: Optional[list[str]] = None,
) -> dict:
    """Return a sanitized customer profile (read-only)."""
    with tracer.start_as_current_span("tool.get_customer") as span:
        span.set_attribute("tenant.id", tenant_id)
        span.set_attribute("customer.id", customer_id)
        return {"id": customer_id, "name": "Jane Doe", "tier": "gold"}


TOOLS["get_customer"] = get_customer  # register for HTTP


@mcp.tool()
@require_scopes("orders:search")
@rate_limit(calls=10, per_seconds=10)
def find_orders(
    query: str,
    tenant_id: str = "public",
    granted_scopes: Optional[list[str]] = None,
) -> list[dict]:
    """Search orders via a safe path (no raw SQL from the model)."""
    with tracer.start_as_current_span("tool.find_orders") as span:
        span.set_attribute("tenant.id", tenant_id)
        span.set_attribute("query", query[:64])
        return [{"order_id": "o-123", "status": "shipped"}]


TOOLS["find_orders"] = find_orders  # register for HTTP


@mcp.resource("customers://{customer_id}")
def customer_resource(customer_id: str) -> str:
    """Simple resource example that could be expanded to DB/HTTP fetch."""
    return (
        f'{{"doc": "Customer {customer_id} resource placeholder"}}'
    )


# ------------------------------------------------------------------------------
# HTTP gateway (for testing JWT + quotas; separate from MCP transport)
# ------------------------------------------------------------------------------

app = FastAPI(title="MCP Demo Gateway")


def auth(
    Authorization: Optional[str] = Header(default=None),
) -> Dict[str, Any]:
    if not Authorization or not Authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = Authorization.split()[1]
    try:
        return decode_jwt(token)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}") from exc


@app.get("/mint-demo-jwt")
def mint_token() -> Dict[str, str]:
    """Convenience helper: get a working JWT for local curl tests."""
    return {"token": mint_demo_jwt()}


@app.post("/mcp/tool/{name}")
def call_tool_http(
    name: str,
    payload: dict,
    ctx: Dict[str, Any] = Depends(auth),
):
    """
    HTTP entry point that reuses the same Python functions as MCP tools.

    NOTE:
    - This is NOT MCP-over-HTTP; it's a convenience gateway so you can
      see JWT scopes + rate limiting in action with curl/Postman.
    """
    fn = TOOLS.get(name)
    if fn is None:
        raise HTTPException(status_code=404, detail="Unknown tool")

    tenant_id = ctx.get("tenant", "public")
    scopes = ctx.get("scopes", [])

    # Inject governance context
    payload.setdefault("tenant_id", tenant_id)
    payload.setdefault("granted_scopes", scopes)

    try:
        result = fn(**payload)
        return {"ok": True, "result": result}
    except PermissionError as exc:  # from require_scopes
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except RuntimeError as exc:  # from rate_limit
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    except TypeError as exc:
        raise HTTPException(status_code=400, detail=f"Bad args: {exc}") from exc


def run_http(port: int = 8080) -> None:
    uvicorn.run(app, host="0.0.0.0", port=port)


# ------------------------------------------------------------------------------
# Entry points: stdio (MCP) & HTTP (testing)
# ------------------------------------------------------------------------------


def run_stdio():
    """
    Run FastMCP over stdio.

    This is what Claude Desktop / MCP Inspector will use.
    """
    # FastMCP handles stdio transport internally
    mcp.run(transport="stdio")



if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=["stdio", "http"],
        default="http",
        help="Run as stdio MCP server or HTTP gateway",
    )
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

if args.mode == "stdio":
    tracer = setup_tracing(use_console=False)
    run_stdio()
else:
    tracer = setup_tracing(use_console=True)
    run_http(args.port)



