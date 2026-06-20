from __future__ import annotations
from typing import Optional

import typer

app = typer.Typer(help="Start the Anti-Venom webhook proxy server.")


@app.callback(invoke_without_command=True)
def serve_command(
    upstream: str = typer.Option(..., "--upstream", "-u", help="Upstream embedding API URL."),
    host: str = typer.Option("0.0.0.0", "--host", help="Host to bind."),
    port: int = typer.Option(8765, "--port", "-p", help="Port to bind."),
    workers: int = typer.Option(1, "--workers", help="Number of uvicorn workers."),
    auth_header: Optional[str] = typer.Option(None, "--auth-header", help="Authorization header to forward upstream."),
    threshold: float = typer.Option(0.7, "--threshold", "-t"),
    no_quarantine: bool = typer.Option(False, "--no-quarantine"),
) -> None:
    """Start a webhook proxy that scans embedding requests in real time."""
    try:
        import uvicorn  # type: ignore[import]
    except ImportError:
        typer.echo("uvicorn is required: pip install antivenom[serve]", err=True)
        raise typer.Exit(1)

    from antivenom.webhook.proxy import create_proxy_app
    from antivenom.core.config import ScannerConfig

    config = ScannerConfig(
        confidence_threshold=threshold,
        quarantine_on_detection=not no_quarantine,
    )
    app_instance = create_proxy_app(upstream_url=upstream, config=config, auth_header=auth_header)

    typer.echo(f"Anti-Venom proxy starting on http://{host}:{port}")
    typer.echo(f"Forwarding clean requests to: {upstream}")
    uvicorn.run(app_instance, host=host, port=port, workers=workers)
