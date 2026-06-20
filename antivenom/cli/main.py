import typer
from antivenom.cli.commands import scan, audit, serve

app = typer.Typer(
    name="antivenom",
    help="RAG Corpus Poisoning Detector — scan documents for adversarial prompt injections.",
    no_args_is_help=True,
)

app.add_typer(scan.app, name="scan")
app.add_typer(audit.app, name="audit")
app.add_typer(serve.app, name="serve")


if __name__ == "__main__":
    app()
