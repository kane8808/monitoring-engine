import typer

from monitoring_engine.runner.main import main

app = typer.Typer()


@app.command()
def run():
    """Run monitoring engine."""
    main()


if __name__ == "__main__":
    app()