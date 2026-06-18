import typer
import json
import yaml
import ev0lutionChamber
from models import Payload, PayloadType, TargetEnvironment
from pathlib import Path

app = typer.Typer(help="Red Team Payload Obfuscation and OpSec Risk Analyzer")


@app.command()
def process(
    payload_path: Path = typer.Argument(..., help="Path to the payload file"),
    env_data_path: Path = typer.Argument(
        ..., help="Path to target environment JSON/YAML"
    ),
    output_path: Path = typer.Option(
        "evasive_payload.bin", help="Output path for the evasive payload"
    ),
):
    """Orchestrates the analysis, transformation, and validation of a payload."""

    # Load Payload
    payload = Payload(
        raw_data=payload_path.read_bytes(),
        payload_type=PayloadType.SHELLCODE,  # Add logic to detect type
    )

    # Load Environment Data
    env_text = env_data_path.read_text()
    try:
        env_dict = json.loads(env_text)
    except json.JSONDecodeError:
        env_dict = yaml.safe_load(env_text)

    target_env = TargetEnvironment(**env_dict)

    # Run Orchestrator
    orchestrator = ev0lutionChamber()
    final_payload = orchestrator.run(payload, target_env)

    # Save Output
    output_path.write_bytes(final_payload.raw_data)
    typer.echo(f"Evasive payload saved to {output_path}")


if __name__ == "__main__":
    app()
