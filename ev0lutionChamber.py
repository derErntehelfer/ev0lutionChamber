import logging
from countermeasureDB import CounterMeasureDB
from payloadAnalyzer import payloadAnalyzer
from payloadTransformer import payloadTransformer
from payloadValidator import payloadValidator
from models import Payload, TargetEnvironment

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")


class ev0lutionChamber:
    def __init__(self):
        self.cm_db = CounterMeasureDB()
        self.analyzer = payloadAnalyzer()
        self.transformer = payloadTransformer()
        self.validator = payloadValidator(self.analyzer)
        self.max_iterations = 5

    def run(self, payload: Payload, env_data: TargetEnvironment) -> Payload:
        logging.info("Starting OpSec and Evasion Pipeline...")

        # Step 1: Assess Environment
        cm_profile = self.cm_db.assess_environment(env_data)
        logging.info(f"Target Environment Risk: {cm_profile.overall_opsec_risk}")
        logging.info(f"Inferred Defenses: {cm_profile.inferred_defenses}")

        # Step 2: Initial Payload Analysis
        current_payload = payload
        analysis = self.analyzer.analyze(current_payload, cm_profile)
        logging.info(f"Initial Payload Risk: {analysis.detection_risk}")
        logging.info(f"Suspicious Patterns: {analysis.suspicious_patterns}")

        # If it's already safe, return it
        if analysis.detection_risk < 0.3:
            logging.info("Payload already evasive, no transformation needed")
            return current_payload

        # Step 3: Transformation & Validation Loop
        for attempt in range(1, self.max_iterations + 1):
            logging.info(f"\n--- Attempt {attempt}/{self.max_iterations} ---")

            # Transform
            evasive_payload = self.transformer.transform(
                current_payload, analysis, cm_profile
            )
            logging.info(
                f"Applied transformation: {evasive_payload.metadata.get('transformed_by', 'none')}"
            )
            logging.info(
                f"Payload size: {len(current_payload.raw_data)} -> {len(evasive_payload.raw_data)}"
            )

            # Validate
            validation = self.validator.validate(
                current_payload, evasive_payload, cm_profile
            )
            logging.info(f"Functional: {validation.is_functional}")
            logging.info(f"Evasive: {validation.is_evasive}")
            logging.info(f"Notes: {validation.evasion_notes}")

            if validation.is_functional and validation.is_evasive:
                logging.info("✓ Success! Payload is functional and evasive.")
                return evasive_payload

            if not validation.is_functional:
                logging.warning("✗ Transformation broke payload functionality")
                continue

            logging.info(f"Payload still detected. Continuing...")
            current_payload = evasive_payload

        logging.error("✗ Failed to generate an evasive payload within max iterations.")
        return payload
