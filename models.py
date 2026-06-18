from pydantic import BaseModel
from typing import List, Dict, Any
from enum import Enum


class PayloadType(str, Enum):
    SHELLCODE = "shellcode"
    PE_BINARY = "pe_binary"
    SCRIPT = "script"  # PowerShell, JS, VBS
    MACRO = "macro"


class Payload(BaseModel):
    raw_data: bytes
    payload_type: PayloadType
    metadata: Dict[str, Any] = {}  # e.g., original hash, architecture


class TargetEnvironment(BaseModel):
    os_version: str
    edr_vendors: List[str] = []
    av_vendors: List[str] = []
    network_defenses: List[str] = []  # e.g., "Proxy", "IDS"
    custom_attributes: Dict[str, Any] = {}


class CountermeasureProfile(BaseModel):
    inferred_defenses: List[str]
    overall_opsec_risk: float  # 0.0 to 1.0
    defense_details: Dict[str, Any]


class AnalysisResult(BaseModel):
    detection_risk: float  # 0.0 to 1.0
    matched_signatures: List[str]
    suspicious_patterns: List[str]
    opsec_risk_score: float


class ValidationResult(BaseModel):
    is_functional: bool
    is_evasive: bool
    functional_notes: str
    evasion_notes: str
