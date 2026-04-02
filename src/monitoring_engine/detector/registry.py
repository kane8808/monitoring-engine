from __future__ import annotations

from .rules.auth_trace_detector import AuthTraceDetector
from .rules.process_trace_detector import ProcessTraceDetector


def get_detectors():
    return [
        AuthTraceDetector(),
        ProcessTraceDetector(),
    ]