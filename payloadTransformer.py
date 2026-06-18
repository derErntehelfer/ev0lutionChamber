import logging
from models import Payload, AnalysisResult, CountermeasureProfile


class payloadTransformer:
    def __init__(self):
        self.strategies = ["xor_encrypt", "api_unhook", "sleep_mask", "pack"]

    def transform(
        self,
        payload: Payload,
        analysis: AnalysisResult,
        countermeasures: CountermeasureProfile,
    ) -> Payload:
        data = payload.raw_data
        applied_transforms = []

        # Remove/obfuscate suspicious patterns
        if "memory_allocation_api" in analysis.suspicious_patterns:
            data = data.replace(
                b"VirtualAlloc",
                b"V\x00i\x00r\x00t\x00u\x00a\x00l\x00A\x00l\x00l\x00o\x00c\x00",
            )
            applied_transforms.append("api_string_split")

        if "process_injection_api" in analysis.suspicious_patterns:
            data = data.replace(
                b"CreateRemoteThread",
                b"C\x00r\x00e\x00a\x00t\x00e\x00R\x00e\x00m\x00o\x00t\x00e\x00T\x00h\x00r\x00e\x00a\x00d\x00",
            )
            applied_transforms.append("api_string_split")

        if "cmd_execution" in analysis.suspicious_patterns:
            data = data.replace(b"cmd.exe", b"cm\x00d\x00.\x00e\x00x\x00e\x00")
            applied_transforms.append("cmd_obfuscation")

        if "powershell_execution" in analysis.suspicious_patterns:
            data = data.replace(
                b"powershell", b"p\x00o\x00w\x00e\x00r\x00s\x00h\x00e\x00l\x00l\x00"
            )
            applied_transforms.append("powershell_obfuscation")

        if "com_object_creation" in analysis.suspicious_patterns:
            data = data.replace(
                b"CreateObject",
                b"C\x00r\x00e\x00a\x00t\x00e\x00O\x00b\x00j\x00e\x00c\x00t\x00",
            )
            applied_transforms.append("com_obfuscation")

        if "http_request" in analysis.suspicious_patterns:
            data = data.replace(b"XMLHTTP", b"X\x00M\x00L\x00H\x00T\x00T\x00P\x00")
            applied_transforms.append("http_obfuscation")

        # If no specific patterns, apply general XOR encryption
        if not applied_transforms:
            data = bytes([b ^ 0xAA for b in data])
            applied_transforms.append("xor_encrypt")

        transform_name = "+".join(applied_transforms)
        logging.info(f"Transformer applied: {transform_name}")

        return Payload(
            raw_data=data,
            payload_type=payload.payload_type,
            metadata={**payload.metadata, "transformed_by": transform_name},
        )

    def _apply_strategy(self, data: bytes, strategy: str) -> bytes:
        # Actual obfuscation logic goes here
        if strategy == "xor_encrypt":
            return bytes([b ^ 0x55 for b in data])
        return data
