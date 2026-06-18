import hashlib
import logging
from models import Payload, AnalysisResult, CountermeasureProfile


class payloadAnalyzer:
    def analyze(
        self, payload: Payload, countermeasures: CountermeasureProfile
    ) -> AnalysisResult:
        # 1. Calculate Hashes
        sha256 = hashlib.sha256(payload.raw_data).hexdigest()

        # 2. Pattern Matching - check for suspicious patterns
        suspicious_patterns = []

        # Check for API calls (these should be obfuscated/removed)
        if b"VirtualAlloc" in payload.raw_data:
            suspicious_patterns.append("memory_allocation_api")
        if b"CreateRemoteThread" in payload.raw_data:
            suspicious_patterns.append("process_injection_api")
        if b"cmd.exe" in payload.raw_data:
            suspicious_patterns.append("cmd_execution")
        if b"powershell" in payload.raw_data.lower():
            suspicious_patterns.append("powershell_execution")
        if b"CreateObject" in payload.raw_data:
            suspicious_patterns.append("com_object_creation")
        if b"XMLHTTP" in payload.raw_data:
            suspicious_patterns.append("http_request")

        # 3. Calculate Risk based on patterns and countermeasures
        base_risk = len(suspicious_patterns) * 0.25  # Each pattern adds 25% risk
        edr_multiplier = 1.0 + (countermeasures.overall_opsec_risk * 0.5)
        final_risk = min(base_risk * edr_multiplier, 1.0)

        logging.info(
            f"Analysis: {len(suspicious_patterns)} patterns found, risk={final_risk:.2f}"
        )

        return AnalysisResult(
            detection_risk=final_risk,
            matched_signatures=[sha256],
            suspicious_patterns=suspicious_patterns,
            opsec_risk_score=final_risk,
        )
