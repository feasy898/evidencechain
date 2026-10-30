"""EvidenceChain - a security-assessment finding pipeline (standard library only).

Four layers: parse -> aggregate -> prioritize -> report.
Ground rule: conclusions come from deterministic rules only, and every conclusion
keeps a `file:line` evidence reference that can be resolved mechanically.
"""

__version__ = "0.1.1"
