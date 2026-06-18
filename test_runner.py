# test_runner.py
import typer
from pathlib import Path
from ev0lutionChamber import ev0lutionChamber
from models import Payload, PayloadType, TargetEnvironment
import json
import yaml

app = typer.Typer()


@app.command()
def run_all_tests():
    """Test all payload/environment combinations"""

    payloads = {
        "suspicious_shellcode": (
            "test_payloads/suspicious_shellcode.bin",
            PayloadType.SHELLCODE,
        ),
        "clean_script": ("test_payloads/clean_script.ps1", PayloadType.SCRIPT),
        "malicious_macro": ("test_payloads/malicious_macro.vbs", PayloadType.SCRIPT),
        "encrypted_payload": (
            "test_payloads/encrypted_payload.bin",
            PayloadType.SHELLCODE,
        ),
    }

    environments = {
        "low_risk": "test_envs/low_risk_env.json",
        "high_risk": "test_envs/high_risk_env.json",
        "medium_risk": "test_envs/medium_risk_env.yaml",
        "legacy": "test_envs/legacy_env.json",
    }

    orchestrator = ev0lutionChamber()

    for payload_name, (payload_path, payload_type) in payloads.items():
        for env_name, env_path in environments.items():
            typer.echo(f"\n{'=' * 60}")
            typer.echo(f"Testing: {payload_name} + {env_name}")
            typer.echo(f"{'=' * 60}")

            try:
                # Load payload
                original_data = Path(payload_path).read_bytes()
                payload = Payload(raw_data=original_data, payload_type=payload_type)

                # Load environment
                env_text = Path(env_path).read_text()
                if env_path.endswith(".json"):
                    env_dict = json.loads(env_text)
                else:
                    env_dict = yaml.safe_load(env_text)

                target_env = TargetEnvironment(**env_dict)

                # Run orchestrator
                result = orchestrator.run(payload, target_env)

                # Check if transformation actually occurred
                was_transformed = result.raw_data != original_data
                transform_info = result.metadata.get("transformed_by", "none")

                if was_transformed:
                    typer.echo(
                        f"✓ SUCCESS: Payload transformed ({len(original_data)} -> {len(result.raw_data)} bytes)"
                    )
                    typer.echo(f"  Transformations: {transform_info}")
                else:
                    if payload_name in ["clean_script"]:
                        typer.echo(f"✓ OK: No transformation needed (already clean)")
                    else:
                        typer.echo(
                            f"✗ FAILED: No transformation applied (still {len(result.raw_data)} bytes)"
                        )
                        typer.echo(f"  Transformations: {transform_info}")

            except Exception as e:
                typer.echo(f"✗ ERROR: {e}", err=True)
                import traceback

                traceback.print_exc()


if __name__ == "__main__":
    app()
