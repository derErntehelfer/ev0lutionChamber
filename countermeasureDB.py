from models import TargetEnvironment, CountermeasureProfile


class CounterMeasureDB:
    def __init__(self, db_path: str = "defenses.yaml"):
        # In reality, load this from a YAML/JSON database
        self.knowledge_base = self._load_db(db_path)

    def _load_db(self, path):
        # Placeholder for DB loading logic
        return {
            "CrowdStrike": {"risk_weight": 0.9, "signatures": ["cs_hook", "cs_indy"]}
        }

    def assess_environment(self, env_data: TargetEnvironment) -> CountermeasureProfile:
        inferred = []
        total_risk = 0.0

        # Logic to match env_data against knowledge_base
        for edr in env_data.edr_vendors:
            if edr in self.knowledge_base:
                inferred.append(edr)
                total_risk += self.knowledge_base[edr]["risk_weight"]

        # Normalize risk to 0.0 - 1.0
        normalized_risk = min(
            total_risk / max(len(env_data.edr_vendors + env_data.av_vendors), 1), 1.0
        )

        return CountermeasureProfile(
            inferred_defenses=inferred,
            overall_opsec_risk=normalized_risk,
            defense_details={"matched_rules": inferred},
        )
