# ev0lutionChamber

**Automated Payload Obfuscation & OpSec Risk Analysis Framework**

> **CURRENT STATUS: Vibe Coded Prototype**  
> *This project is currently a "vibe coded" prototype. The core architecture, data flow, and feedback loops are fully functional, but the underlying engines (static analysis, sandbox emulation, advanced obfuscation) are currently using placeholder logic. Expect bugs, rough edges, and rapid iteration.*

## Overview

`ev0lutionChamber` is a modular Red Team CLI tool designed to automate the payload obfuscation process. Instead of manually guessing which obfuscation techniques will bypass a specific target's defenses, this tool ingests target environment reconnaissance data, assesses the OpSec risk, and iteratively mutates the payload until it is both evasive and functional.

## Architecture

The tool is built on a continuous feedback loop consisting of five core components:

1. **ev0lutionChamber:** The brain of the operation. Manages the data flow, handles the transformation/validation loop, and decides when a payload is "good enough."
2. **CounterMeasure DB:** Ingests target environment data (JSON/YAML from recon) and infers likely defensive countermeasures (EDR, AV, Network) to calculate a baseline OpSec risk.
3. **Payload Analyzer:** Performs static analysis, hashing, and pattern matching against the assumed countermeasures to calculate the payload's specific detection risk.
4. **Payload Transformer:** Suggests and applies obfuscation techniques (XOR, API unhooking, string splitting, etc.) based on what triggered the detection.
5. **Payload Validator:** The quality control gate. Checks if the transformed payload is still functionally intact and re-queries the Analyzer to verify the evasion was successful.

## Usage

This project uses [`uv`](https://github.com/astral-sh/uv) for fast dependency management and execution.

### Run the CLI
```bash
uv run ev0CommandLineInterface.py process <payload_file> <env_data_file> -o <output_file>
```

### Run the Test Suite

To test the data flow across various faux payloads and environment configurations:

```bash
uv run test_runner.py
```

## TODO

Since this is a vibe-coded prototype, the next steps involve replacing the placeholder logic with real-world engines:

    Integrate real YARA rule scanning in the PayloadAnalyzer.
    Replace the placeholder _check_functionality in the PayloadValidator with actual AST parsing (for scripts) or a lightweight emulator like Unicorn/Qiling (for shellcode).
    Expand the PayloadTransformer with a Strategy pattern to support real obfuscation engines (e.g., LLVM-based obfuscation, actual API hashing/unhooking).
    Build out the CounterMeasureDB with a comprehensive, updatable YAML/JSON database of real-world EDR/AV behavioral heuristics.
