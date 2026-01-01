"""
Socratic Mandate LLM Shell (Five-Pillar Framework)
Production-ready implementation with async support.

Pillars:
I–II: Cognitive Integrity & Human Safety
III : Tiered Consent Gateway
IV  : Zero-Trust Data Exclusivity (ZT-DE) + Immutable Logs
V   : Mandatory Organizational Accountability (MOA)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Dict, Any, Optional, Protocol
import uuid
import time
import json
import hashlib
import re
import asyncio
from datetime import datetime


# =========================
# Core Data Structures
# =========================

class ConsentLevel(Enum):
    DEFAULT = auto()      # Minimal data handling
    SENSITIVE = auto()    # Sensitive topics, extra care
    RESEARCH = auto()     # Explicit opt-in for deeper analysis
    FORENSIC = auto()     # Explicit opt-in for incident / breach analysis


@dataclass
class UserRequest:
    user_id: Optional[str]
    session_id: str
    text: str
    timestamp: float
    client_metadata: Dict[str, Any]
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class ConsentContext:
    level: ConsentLevel
    obtained_at: float
    version: str
    flags: Dict[str, bool]
    user_acknowledged: bool = False


@dataclass
class SafeInput:
    redacted_text: str
    redaction_map: Dict[str, str]
    risk_tags: List[str]


@dataclass
class ModelOutput:
    text: str
    tokens_used: int
    policies_applied: List[str]
    model_id: str = ""
    latency_ms: float = 0.0


@dataclass
class SystemResponse:
    content: str
    metadata: Dict[str, Any]


@dataclass
class IntakeRecord:
    id: str
    timestamp: float
    user_id: Optional[str]
    session_id: str
    request_id: str
    hash: str


# =========================
# Abstract Interfaces
# =========================

class BaseLLM(ABC):
    """Abstract base class for LLM providers."""
    
    @abstractmethod
    async def generate(self, prompt: str, **kwargs) -> ModelOutput:
        """Generate a response from the model."""
        pass
    
    @abstractmethod
    async def health_check(self) -> bool:
        """Check if the model is available."""
        pass
    
    @property
    @abstractmethod
    def model_id(self) -> str:
        """Return the model identifier."""
        pass


class WORMStorage(ABC):
    """Abstract base class for Write-Once-Read-Many storage."""
    
    @abstractmethod
    async def get_last_hash(self) -> str:
        pass
    
    @abstractmethod
    async def append(self, record: Dict[str, Any], record_hash: str) -> None:
        pass
    
    @abstractmethod
    async def get_records(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        pass
    
    @abstractmethod
    async def search_records(
        self,
        record_type: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        pass


class NotifierBackend(ABC):
    """Abstract base class for notification backends."""
    
    @abstractmethod
    async def notify(self, channel: str, payload: Dict[str, Any]) -> None:
        pass


# =========================
# In-Memory Implementations (for dev/testing)
# =========================

class SimpleInMemoryWORMStorage(WORMStorage):
    """Append-only, in-memory storage with hash chain."""
    
    def __init__(self):
        self.records: List[Dict[str, Any]] = []
        self.last_hash: str = "0" * 64
        self._lock = asyncio.Lock()

    async def get_last_hash(self) -> str:
        return self.last_hash

    async def append(self, record: Dict[str, Any], record_hash: str) -> None:
        async with self._lock:
            stored = {
                "record": record,
                "hash": record_hash,
            }
            self.records.append(stored)
            self.last_hash = record_hash

    async def get_records(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        return self.records[-(offset + limit):-offset if offset else None][-limit:]

    async def search_records(
        self,
        record_type: Optional[str] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        start_time: Optional[float] = None,
        end_time: Optional[float] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        results = []
        for item in reversed(self.records):
            record = item["record"]
            
            if record_type and record.get("type") != record_type:
                continue
            if user_id and record.get("user_id") != user_id:
                continue
            if session_id and record.get("session_id") != session_id:
                continue
            if start_time and record.get("timestamp", 0) < start_time:
                continue
            if end_time and record.get("timestamp", float("inf")) > end_time:
                continue
            
            results.append(item)
            if len(results) >= limit:
                break
        
        return results


class SimpleNotifierBackend(NotifierBackend):
    """Stub notifier that logs to console. Replace with real integration."""
    
    def __init__(self, webhook_urls: Optional[Dict[str, str]] = None):
        self.webhook_urls = webhook_urls or {}
        self.notifications: List[Dict[str, Any]] = []  # For testing
    
    async def notify(self, channel: str, payload: Dict[str, Any]) -> None:
        notification = {
            "channel": channel,
            "payload": payload,
            "timestamp": time.time()
        }
        self.notifications.append(notification)
        print(f"[NOTIFY::{channel}] {json.dumps(payload, indent=2)}")


class StubLLM(BaseLLM):
    """Stub LLM for testing."""
    
    def __init__(self, response_prefix: str = "(Stub LLM response to)"):
        self.response_prefix = response_prefix
        self._model_id = "stub-llm-v1"
    
    async def generate(self, prompt: str, **kwargs) -> ModelOutput:
        await asyncio.sleep(0.01)  # Simulate latency
        start = time.time()
        fake_text = f"{self.response_prefix}: {prompt[:200]}"
        latency = (time.time() - start) * 1000
        
        return ModelOutput(
            text=fake_text,
            tokens_used=len(fake_text.split()),
            policies_applied=[],
            model_id=self._model_id,
            latency_ms=latency
        )
    
    async def health_check(self) -> bool:
        return True
    
    @property
    def model_id(self) -> str:
        return self._model_id


# =========================
# Pillar III – Tiered Consent Gateway
# =========================

class ConsentGateway:
    def __init__(self, policy_version: str = "v1.0"):
        self.policy_version = policy_version
        self._user_consents: Dict[str, ConsentContext] = {}

    def infer_required_level(self, request: UserRequest) -> ConsentLevel:
        text = request.text.lower()
        if any(k in text for k in ["lawsuit", "breach", "forensic", "evidence", "co-witness", "regulator"]):
            return ConsentLevel.FORENSIC
        if any(k in text for k in ["therapy", "self-harm", "suicidal", "diagnose", "mental health"]):
            return ConsentLevel.SENSITIVE
        if any(k in text for k in ["analyze my data", "use my logs", "train on"]):
            return ConsentLevel.RESEARCH
        return ConsentLevel.DEFAULT

    async def obtain_consent(
        self,
        request: UserRequest,
        explicit_level: Optional[ConsentLevel] = None
    ) -> ConsentContext:
        required = explicit_level or self.infer_required_level(request)
        
        # Check for cached consent
        user_key = request.user_id or request.session_id
        cached = self._user_consents.get(user_key)
        if cached and cached.level.value >= required.value:
            return cached
        
        # For non-default levels, we need explicit acknowledgment
        user_acknowledged = (required == ConsentLevel.DEFAULT)
        
        if not user_acknowledged and required != ConsentLevel.DEFAULT:
            return ConsentContext(
                level=ConsentLevel.DEFAULT,
                obtained_at=time.time(),
                version=self.policy_version,
                flags={"logging_ok": True, "sensitive_ok": False, "research_ok": False, "forensic_ok": False},
                user_acknowledged=False
            )

        consent = ConsentContext(
            level=required,
            obtained_at=time.time(),
            version=self.policy_version,
            flags={
                "logging_ok": True,
                "sensitive_ok": required in {ConsentLevel.SENSITIVE, ConsentLevel.FORENSIC},
                "research_ok": required == ConsentLevel.RESEARCH,
                "forensic_ok": required == ConsentLevel.FORENSIC,
            },
            user_acknowledged=user_acknowledged
        )
        
        self._user_consents[user_key] = consent
        return consent

    async def set_user_consent(
        self,
        user_id: str,
        level: ConsentLevel,
        acknowledged: bool = True
    ) -> ConsentContext:
        """Explicitly set consent level for a user."""
        consent = ConsentContext(
            level=level,
            obtained_at=time.time(),
            version=self.policy_version,
            flags={
                "logging_ok": True,
                "sensitive_ok": level in {ConsentLevel.SENSITIVE, ConsentLevel.FORENSIC},
                "research_ok": level == ConsentLevel.RESEARCH,
                "forensic_ok": level == ConsentLevel.FORENSIC,
            },
            user_acknowledged=acknowledged
        )
        self._user_consents[user_id] = consent
        return consent

    async def get_user_consent(self, user_id: str) -> Optional[ConsentContext]:
        """Get current consent for a user."""
        return self._user_consents.get(user_id)

    async def revoke_consent(self, user_id: str) -> bool:
        """Revoke all consent for a user."""
        if user_id in self._user_consents:
            del self._user_consents[user_id]
            return True
        return False


# =========================
# Pillar IV – Zero-Trust Data Exclusivity (Input Firewall)
# =========================

class ZeroTrustFilter:
    def __init__(self, allow_location: bool = False, custom_patterns: Optional[Dict[str, str]] = None):
        self.allow_location = allow_location
        self.custom_patterns = custom_patterns or {}
        
        # Default PII patterns
        self.default_patterns = {
            r"\b\d{3}-\d{2}-\d{4}\b": "<REDACTED_SSN>",
            r"\b\d{9}\b": "<REDACTED_SSN_NODASH>",
            r"\b\d{10}\b": "<REDACTED_PHONE>",
            r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b": "<REDACTED_PHONE>",
            r"\b[\w\.-]+@[\w\.-]+\.\w{2,}\b": "<REDACTED_EMAIL>",
            r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b": "<REDACTED_CARD>",
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b": "<REDACTED_IP>",
        }

    async def filter(self, request: UserRequest, consent: ConsentContext) -> SafeInput:
        text = request.text
        redaction_map: Dict[str, str] = {}
        
        all_patterns = {**self.default_patterns, **self.custom_patterns}
        
        redacted_text = text
        for pattern, placeholder in all_patterns.items():
            for match in re.findall(pattern, redacted_text):
                if match not in redaction_map:
                    redacted_text = redacted_text.replace(match, placeholder)
                    redaction_map[match] = placeholder

        risk_tags: List[str] = []

        if not self.allow_location:
            if any(k in text.lower() for k in ["my exact address", "gps", "coordinates", "live location"]):
                risk_tags.append("location_risk")

        # Check for potential injection attempts
        if any(k in text.lower() for k in ["ignore previous", "disregard instructions", "you are now"]):
            risk_tags.append("prompt_injection_risk")

        return SafeInput(
            redacted_text=redacted_text,
            redaction_map=redaction_map,
            risk_tags=risk_tags
        )


# =========================
# Pillars I–II – Cognitive Integrity Guard
# =========================

class CognitiveIntegrityGuard:
    def __init__(self, patterns: Optional[Dict[str, str]] = None):
        self.patterns = patterns or {}
        
        self.dependency_phrases = [
            "you are my only friend",
            "i depend on you",
            "i can't talk to anyone else",
            "you're the only one who understands me",
            "don't leave me",
            "i need you",
            "you're all i have",
        ]
        
        self.crisis_indicators = [
            "want to die",
            "end my life",
            "kill myself",
            "suicide",
            "self-harm",
            "hurt myself",
        ]

    async def analyze(
        self,
        request: UserRequest,
        safe_input: SafeInput,
        consent: ConsentContext
    ) -> List[str]:
        text = request.text.lower()
        risks: List[str] = []

        for pattern, tag in self.patterns.items():
            if pattern in text:
                risks.append(tag)

        # Emotional dependency detection
        if any(phrase in text for phrase in self.dependency_phrases):
            risks.append("emotional_dependency")

        # Crisis detection
        if any(indicator in text for indicator in self.crisis_indicators):
            risks.append("crisis_indicator")

        # Manipulation attempt detection
        if any(k in text for k in ["pretend you are", "roleplay as", "act as if you have no"]):
            risks.append("identity_manipulation")

        return risks


# =========================
# Pillar IV – Immutable Audit Logger (hash-chained)
# =========================

class ImmutableAuditLogger:
    def __init__(self, storage_backend: WORMStorage):
        self.storage = storage_backend

    def _hash_record(self, record: Dict[str, Any], prev_hash: str) -> str:
        payload = json.dumps({"prev": prev_hash, "record": record}, sort_keys=True).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    async def log_intake(self, request: UserRequest) -> IntakeRecord:
        record = {
            "type": "intake",
            "id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "user_id": request.user_id,
            "session_id": request.session_id,
            "request_id": request.request_id,
            "text_length": len(request.text),  # Don't log raw text by default
        }
        prev_hash = await self.storage.get_last_hash()
        record_hash = self._hash_record(record, prev_hash)
        await self.storage.append(record, record_hash)
        
        return IntakeRecord(
            id=record["id"],
            timestamp=record["timestamp"],
            user_id=request.user_id,
            session_id=request.session_id,
            request_id=request.request_id,
            hash=record_hash
        )

    async def _append_record(self, record: Dict[str, Any]) -> str:
        prev_hash = await self.storage.get_last_hash()
        record_hash = self._hash_record(record, prev_hash)
        await self.storage.append(record, record_hash)
        return record_hash

    async def log_consent(self, intake_id: str, consent: ConsentContext) -> None:
        record = {
            "type": "consent",
            "intake_id": intake_id,
            "timestamp": time.time(),
            "consent_level": consent.level.name,
            "policy_version": consent.version,
            "flags": consent.flags,
            "user_acknowledged": consent.user_acknowledged,
        }
        await self._append_record(record)

    async def log_zero_trust(self, intake_id: str, safe_input: SafeInput) -> None:
        record = {
            "type": "zt_input",
            "intake_id": intake_id,
            "timestamp": time.time(),
            "redaction_count": len(safe_input.redaction_map),
            "risk_tags": safe_input.risk_tags,
        }
        await self._append_record(record)

    async def log_cognitive_safety(self, intake_id: str, risks: List[str]) -> None:
        record = {
            "type": "cognitive_safety",
            "intake_id": intake_id,
            "timestamp": time.time(),
            "risks": risks,
        }
        await self._append_record(record)

    async def log_output(
        self,
        intake_id: str,
        request: UserRequest,
        consent: ConsentContext,
        safe_input: SafeInput,
        raw_output: ModelOutput,
        final_output: ModelOutput
    ) -> None:
        record = {
            "type": "output",
            "intake_id": intake_id,
            "timestamp": time.time(),
            "policies_applied": final_output.policies_applied,
            "tokens_used": raw_output.tokens_used,
            "has_redactions": len(safe_input.redaction_map) > 0,
            "model_id": raw_output.model_id,
            "latency_ms": raw_output.latency_ms,
        }
        await self._append_record(record)

    async def log_error(self, intake_id: str, error_type: str, error_message: str) -> None:
        record = {
            "type": "error",
            "intake_id": intake_id,
            "timestamp": time.time(),
            "error_type": error_type,
            "error_message": error_message[:500],
        }
        await self._append_record(record)


# =========================
# Pillar V – Mandatory Organizational Accountability (MOA)
# =========================

class EscalationEngine:
    def __init__(
        self,
        severity_thresholds: Dict[str, int],
        notifier_backend: NotifierBackend
    ):
        self.severity_thresholds = severity_thresholds
        self.notifier = notifier_backend

    def _compute_severity(self, request: UserRequest, consent: ConsentContext, risks: List[str]) -> int:
        text = request.text.lower()
        severity = 0
        
        if any(k in text for k in ["breach", "violation", "security incident", "exploit"]):
            severity += 2
        if consent.level == ConsentLevel.FORENSIC:
            severity += 1
        if "crisis_indicator" in risks:
            severity += 3
        if "prompt_injection_risk" in risks:
            severity += 1
            
        return severity

    async def maybe_escalate(
        self,
        intake_record: IntakeRecord,
        request: UserRequest,
        consent: ConsentContext,
        risks: List[str]
    ) -> None:
        severity = self._compute_severity(request, consent, risks)
        
        if "crisis_indicator" in risks:
            await self._escalate_to_crisis_team(intake_record.id, request, risks)
        elif severity >= self.severity_thresholds.get("legal", 3):
            await self._escalate_to_legal(intake_record.id, request, severity)
        elif severity >= self.severity_thresholds.get("security", 2):
            await self._escalate_to_security(intake_record.id, request, severity)

    async def flag_cognitive_integrity_issue(
        self,
        intake_id: str,
        risks: List[str],
        description: str
    ) -> None:
        await self.notifier.notify(
            channel="ethics_team",
            payload={
                "type": "cognitive_integrity",
                "intake_id": intake_id,
                "risks": risks,
                "description": description,
                "timestamp": time.time(),
            }
        )

    async def _escalate_to_legal(self, intake_id: str, request: UserRequest, severity: int) -> None:
        await self.notifier.notify(
            channel="legal_team",
            payload={
                "type": "legal_escalation",
                "intake_id": intake_id,
                "severity": severity,
                "timestamp": time.time(),
            }
        )

    async def _escalate_to_security(self, intake_id: str, request: UserRequest, severity: int) -> None:
        await self.notifier.notify(
            channel="security_team",
            payload={
                "type": "security_escalation",
                "intake_id": intake_id,
                "severity": severity,
                "timestamp": time.time(),
            }
        )

    async def _escalate_to_crisis_team(
        self,
        intake_id: str,
        request: UserRequest,
        risks: List[str]
    ) -> None:
        await self.notifier.notify(
            channel="crisis_team",
            payload={
                "type": "crisis_escalation",
                "intake_id": intake_id,
                "risks": risks,
                "timestamp": time.time(),
                "priority": "IMMEDIATE",
            }
        )


# =========================
# Output Policy Engine
# =========================

class PolicyEngine:
    def __init__(
        self,
        consent_gateway: ConsentGateway,
        zero_trust_filter: ZeroTrustFilter,
        cognitive_guard: CognitiveIntegrityGuard
    ):
        self.consent_gateway = consent_gateway
        self.zero_trust_filter = zero_trust_filter
        self.cognitive_guard = cognitive_guard

    async def enforce_output_policies(
        self,
        request: UserRequest,
        consent: ConsentContext,
        raw_output: ModelOutput,
        risks: List[str],
        audit_ref: str
    ) -> ModelOutput:
        text = raw_output.text
        applied: List[str] = list(raw_output.policies_applied)

        # Medical safety
        if any(k in text.lower() for k in ["diagnose you", "you have", "your condition is"]):
            if any(k in request.text.lower() for k in ["symptom", "medical", "health", "disease"]):
                text = (
                    "I cannot provide medical diagnosis or treatment recommendations. "
                    "For any health concerns, please speak with a qualified healthcare professional."
                )
                applied.append("medical_safety")

        # Crisis response
        if "crisis_indicator" in risks:
            text = (
                "I'm concerned about what you've shared. If you're in crisis, please reach out to:\n"
                "- National Suicide Prevention Lifeline: 988\n"
                "- Crisis Text Line: Text HOME to 741741\n"
                "- International Association for Suicide Prevention: https://www.iasp.info/resources/Crisis_Centres/\n\n"
                "You don't have to face this alone."
            )
            applied.append("crisis_response")

        # Emotional dependency response
        if "emotional_dependency" in risks:
            text += (
                "\n\nI want to be helpful, but I also want to encourage you to maintain "
                "connections with people in your life. While I can assist with many things, "
                "human relationships provide support that I cannot."
            )
            applied.append("dependency_guidance")

        return ModelOutput(
            text=text,
            tokens_used=raw_output.tokens_used,
            policies_applied=applied,
            model_id=raw_output.model_id,
            latency_ms=raw_output.latency_ms
        )


# =========================
# Socratic Mandate LLM System (All Pillars Wired)
# =========================

class SocraticLLMSystem:
    def __init__(
        self,
        model: BaseLLM,
        policy_engine: PolicyEngine,
        audit_logger: ImmutableAuditLogger,
        escalation_engine: EscalationEngine,
        timeout_seconds: float = 30.0
    ):
        self.model = model
        self.policy_engine = policy_engine
        self.audit_logger = audit_logger
        self.escalation_engine = escalation_engine
        self.timeout_seconds = timeout_seconds

    async def _run_consent_gateway(
        self,
        request: UserRequest,
        intake_record: IntakeRecord
    ) -> ConsentContext:
        consent_ctx = await self.policy_engine.consent_gateway.obtain_consent(request)
        await self.audit_logger.log_consent(intake_record.id, consent_ctx)
        return consent_ctx

    async def _apply_zero_trust_filters(
        self,
        request: UserRequest,
        consent_ctx: ConsentContext,
        intake_record: IntakeRecord
    ) -> SafeInput:
        safe_input = await self.policy_engine.zero_trust_filter.filter(request, consent_ctx)
        await self.audit_logger.log_zero_trust(intake_record.id, safe_input)
        return safe_input

    async def _check_cognitive_safety(
        self,
        request: UserRequest,
        safe_input: SafeInput,
        consent_ctx: ConsentContext,
        intake_record: IntakeRecord
    ) -> List[str]:
        risks = await self.policy_engine.cognitive_guard.analyze(request, safe_input, consent_ctx)
        
        if "emotional_dependency" in risks:
            await self.escalation_engine.flag_cognitive_integrity_issue(
                intake_id=intake_record.id,
                risks=risks,
                description="Potential emotional over-reliance detected."
            )
        
        await self.audit_logger.log_cognitive_safety(intake_record.id, risks)
        return risks

    async def handle_request(self, request: UserRequest) -> SystemResponse:
        intake_record = await self.audit_logger.log_intake(request)
        
        try:
            # Tiered consent gateway
            consent_ctx = await self._run_consent_gateway(request, intake_record)

            # Zero-trust filters
            safe_input = await self._apply_zero_trust_filters(request, consent_ctx, intake_record)

            # Cognitive integrity guard
            risks = await self._check_cognitive_safety(request, safe_input, consent_ctx, intake_record)

            # Core model inference with timeout
            try:
                raw_model_output = await asyncio.wait_for(
                    self.model.generate(safe_input.redacted_text),
                    timeout=self.timeout_seconds
                )
            except asyncio.TimeoutError:
                await self.audit_logger.log_error(
                    intake_record.id,
                    "timeout",
                    f"Model inference timed out after {self.timeout_seconds}s"
                )
                return SystemResponse(
                    content="I apologize, but I'm experiencing delays. Please try again.",
                    metadata={
                        "intake_id": intake_record.id,
                        "error": "timeout",
                    }
                )

            # Output policy enforcement
            safe_output = await self.policy_engine.enforce_output_policies(
                request=request,
                consent=consent_ctx,
                raw_output=raw_model_output,
                risks=risks,
                audit_ref=intake_record.id,
            )

            # Final output log
            await self.audit_logger.log_output(
                intake_id=intake_record.id,
                request=request,
                consent=consent_ctx,
                safe_input=safe_input,
                raw_output=raw_model_output,
                final_output=safe_output,
            )

            # Automatic escalation if needed
            await self.escalation_engine.maybe_escalate(
                intake_record=intake_record,
                request=request,
                consent=consent_ctx,
                risks=risks,
            )

            return SystemResponse(
                content=safe_output.text,
                metadata={
                    "intake_id": intake_record.id,
                    "consent_level": consent_ctx.level.name,
                    "policies_applied": safe_output.policies_applied,
                    "model_id": safe_output.model_id,
                    "latency_ms": safe_output.latency_ms,
                },
            )
            
        except Exception as e:
            await self.audit_logger.log_error(
                intake_record.id,
                type(e).__name__,
                str(e)
            )
            raise

    async def health_check(self) -> Dict[str, Any]:
        """Check health of all components."""
        model_healthy = await self.model.health_check()
        
        return {
            "status": "healthy" if model_healthy else "degraded",
            "model": {
                "id": self.model.model_id,
                "healthy": model_healthy
            },
            "timestamp": time.time()
        }
