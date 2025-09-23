import secrets
from typing import Optional

import typer
import uvicorn

from app.core.config import get_settings

cli = typer.Typer(help="Service CLI")


@cli.command()
def runserver(host: str = "127.0.0.1", port: int = 8000, reload: bool = False, workers: Optional[int] = None):
    """Run the API using Uvicorn (optionally with reload or multiple workers)."""
    uvicorn.run(
        "app.main:create_app",
        host=host,
        port=port,
        reload=reload,
        workers=workers,
        factory=True,
    )


@cli.command("gen-secret")
def gen_secret():
    """Generate a hex secret suitable for local HS256 tokens."""
    print(secrets.token_hex(32))


if __name__ == "__main__":
    cli()
