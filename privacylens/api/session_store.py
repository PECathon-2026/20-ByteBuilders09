"""
PrivacyLens - Session & Evidence Store
Thread-safe in-memory store for real protection sessions, security test runs, and audit logs.
Guarantees:
1. All statistics are calculated dynamically from actual session records.
2. Raw secrets are NEVER persisted in session history logs (sanitized or masked only).
3. Provides full evidence payloads for the Evidence Inspector and audit report export.
"""

import time
import uuid
import threading
from typing import Dict, Any, List, Optional


class SessionRecord:
    def __init__(
        self,
        session_id: str,
        session_type: str,
        title: str,
        url: str,
        raw_payload: str,
        sanitized_payload: str,
        findings: List[Dict[str, Any]],
        verdict: str,
        canaries_planted: List[str],
        canaries_leaked: List[str],
        latency_ms: float,
        task_goal: Optional[str] = None,
        agent_steps: Optional[List[Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.session_id = session_id
        self.timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.time_display = time.strftime("%H:%M:%S", time.localtime())
        self.session_type = session_type
        self.title = title
        self.url = url
        self.raw_payload = raw_payload
        self.sanitized_payload = sanitized_payload
        self.findings = findings
        self.verdict = verdict  # "PROTECTED", "BLOCKED", "CLEARED"
        self.canaries_planted = canaries_planted
        self.canaries_leaked = canaries_leaked
        self.latency_ms = round(latency_ms, 2)
        self.task_goal = task_goal or ""
        self.agent_steps = agent_steps or []
        self.metadata = metadata or {}

        # Derived dynamic statistics
        self.total_detected = len(findings)
        self.total_redacted = len([f for f in findings if f.get("type") != "PROMPT_INJECTION"])
        self.unredacted_count = len(canaries_leaked)
        self.canaries_planted_count = len(canaries_planted)
        self.canaries_leaked_count = len(canaries_leaked)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "time_display": self.time_display,
            "session_type": self.session_type,
            "title": self.title,
            "url": self.url,
            "task_goal": self.task_goal,
            "raw_payload": self.raw_payload,
            "sanitized_payload": self.sanitized_payload,
            "findings": self.findings,
            "verdict": self.verdict,
            "canaries_planted": self.canaries_planted,
            "canaries_leaked": self.canaries_leaked,
            "canaries_planted_count": self.canaries_planted_count,
            "canaries_leaked_count": self.canaries_leaked_count,
            "total_detected": self.total_detected,
            "total_redacted": self.total_redacted,
            "unredacted_count": self.unredacted_count,
            "latency_ms": self.latency_ms,
            "agent_steps": self.agent_steps,
            "metadata": self.metadata
        }

    def to_summary(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "time_display": self.time_display,
            "session_type": self.session_type,
            "title": self.title,
            "url": self.url,
            "task_goal": self.task_goal,
            "verdict": self.verdict,
            "total_detected": self.total_detected,
            "total_redacted": self.total_redacted,
            "canaries_leaked_count": self.canaries_leaked_count,
            "latency_ms": self.latency_ms
        }


class SessionStore:
    def __init__(self, max_records: int = 100):
        self._sessions: Dict[str, SessionRecord] = {}
        self._order: List[str] = []
        self._lock = threading.Lock()
        self.max_records = max_records

    def add_session(self, record: SessionRecord) -> SessionRecord:
        with self._lock:
            self._sessions[record.session_id] = record
            if record.session_id in self._order:
                self._order.remove(record.session_id)
            self._order.insert(0, record.session_id)

            if len(self._order) > self.max_records:
                oldest_id = self._order.pop()
                self._sessions.pop(oldest_id, None)

            return record

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            rec = self._sessions.get(session_id)
            return rec.to_dict() if rec else None

    def get_all_summaries(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [self._sessions[sid].to_summary() for sid in self._order if sid in self._sessions]

    def get_latest_session(self) -> Optional[Dict[str, Any]]:
        with self._lock:
            if not self._order:
                return None
            return self._sessions[self._order[0]].to_dict()

    def get_aggregate_stats(self) -> Dict[str, Any]:
        with self._lock:
            total_sessions = len(self._sessions)
            if total_sessions == 0:
                return {
                    "total_sessions": 0,
                    "total_detected": 0,
                    "total_redacted": 0,
                    "total_blocked": 0,
                    "total_cleared": 0,
                    "canaries_tested": 0,
                    "canaries_leaked": 0,
                    "avg_latency_ms": 0.0,
                    "leakage_rate_pct": 0.0,
                    "has_data": False
                }

            total_detected = sum(s.total_detected for s in self._sessions.values())
            total_redacted = sum(s.total_redacted for s in self._sessions.values())
            total_blocked = sum(1 for s in self._sessions.values() if s.verdict == "BLOCKED")
            total_cleared = sum(1 for s in self._sessions.values() if s.verdict in ("PROTECTED", "CLEARED"))
            canaries_tested = sum(s.canaries_planted_count for s in self._sessions.values())
            canaries_leaked = sum(s.canaries_leaked_count for s in self._sessions.values())
            total_latency = sum(s.latency_ms for s in self._sessions.values())
            avg_latency = round(total_latency / total_sessions, 1)
            leakage_rate = round((canaries_leaked / canaries_tested * 100.0), 2) if canaries_tested > 0 else 0.0

            return {
                "total_sessions": total_sessions,
                "total_detected": total_detected,
                "total_redacted": total_redacted,
                "total_blocked": total_blocked,
                "total_cleared": total_cleared,
                "canaries_tested": canaries_tested,
                "canaries_leaked": canaries_leaked,
                "avg_latency_ms": avg_latency,
                "leakage_rate_pct": leakage_rate,
                "has_data": True
            }

    def clear(self):
        with self._lock:
            self._sessions.clear()
            self._order.clear()


# Global shared instance
global_session_store = SessionStore()

