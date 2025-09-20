# src/detection/mitre.py
import re
from typing import List, Dict, Optional
from functools import lru_cache

# Minimal local mapping: keyword -> (mitre_id, mitre_name, base_score)
# Expand this aggressively for your use-case.
MITRE_KEYWORD_MAP = {
    # Commands / shell
    r"\bbash\s+-i\b": ("T1059", "Command and Scripting Interpreter", 8),
    r"\bsh\s+-i\b": ("T1059", "Command and Scripting Interpreter", 8),
    r"\bnetcat\b|\bnc\b": ("T1572", "Protocol Tunneling / Netcat", 7),  # approximate
    r"\bbase64\s+-d\b": ("T1140", "Deobfuscate/Decode Files or Information", 6),

    # Web/file download
    r"\bwget\b": ("T1105", "Ingress Tool Transfer", 7),
    r"\bcurl\b": ("T1105", "Ingress Tool Transfer", 7),

    # Recon / scanning
    r"\bnmap\b": ("T1595", "Active Scanning", 6),
    r"\bmasscan\b": ("T1595", "Active Scanning", 6),

    # Persistence / suspicious DLL or autorun pattern examples
    r"powershell\s": ("T1059.001", "PowerShell", 8),

    # SQL / injection-ish
    r"\bunion\s+select\b": ("T1190", "Exploit Public-Facing Application", 7),
    r"select\s+.*from\b": ("T1190", "Exploit Public-Facing Application", 4),

    # Example malware families / miners
    r"xmrig|minergate|coinhive": ("S0448", "Crypto-Mining", 8),
}

# compile regexes once for speed
_COMPILED = [(re.compile(k, re.IGNORECASE), v) for k, v in MITRE_KEYWORD_MAP.items()]


def normalize_text(s: str) -> str:
    """Lower + strip helper for content normalization."""
    return s.lower().strip() if s else ""


@lru_cache(maxsize=4096)
def _match_text_cached(text: str) -> List[Dict]:
    """
    Internal cached matcher: returns list of raw matches for a single text blob.
    Using LRU cache drastically speeds up repeated checks for the same content.
    """
    results = []
    t = normalize_text(text)
    for regex, (tech_id, tech_name, base_score) in _COMPILED:
        m = regex.search(t)
        if m:
            results.append({
                "technique_id": tech_id,
                "technique_name": tech_name,
                "matched_text": m.group(0),
                "base_score": base_score,
            })
    return results


def get_mitre(indicators: Optional[List[str]] = None,
              content: Optional[str] = None,
              min_score_threshold: int = 0) -> List[Dict]:
    """
    Map indicators and content to MITRE techniques (local matching).

    Args:
      indicators: list of short indicator strings (IPs, domains, filenames, commands)
      content: big text blob to scan (log line, payload, script)
      min_score_threshold: drop matches whose aggregated score < threshold

    Returns:
      List[dict] each with:
        - technique_id
        - technique_name
        - matched_terms (list)
        - score (aggregated)
        - confidence (0..1)  # simple based on score caps, not ML
    """
    matches = {}  # key = technique_id -> aggregate info

    # scan indicators (short bits)
    if indicators:
        for ind in indicators:
            if not ind: 
                continue
            for m in _match_text_cached(ind):
                tid = m["technique_id"]
                rec = matches.setdefault(tid, {
                    "technique_id": tid,
                    "technique_name": m["technique_name"],
                    "matched_terms": set(),
                    "score": 0,
                })
                rec["matched_terms"].add(m["matched_text"])
                rec["score"] += m["base_score"]

    # scan larger content blob once
    if content:
        for m in _match_text_cached(content):
            tid = m["technique_id"]
            rec = matches.setdefault(tid, {
                "technique_id": tid,
                "technique_name": m["technique_name"],
                "matched_terms": set(),
                "score": 0,
            })
            rec["matched_terms"].add(m["matched_text"])
            # content matches are slightly stronger
            rec["score"] += int(m["base_score"] * 1.2)

    # finalize list: compute confidence and filter
    out = []
    for tid, rec in matches.items():
        score = rec["score"]
        if score < min_score_threshold:
            continue
        # simple confidence mapping: cap score to 20 -> scale 0..1
        confidence = min(1.0, score / 20.0)
        out.append({
            "technique_id": rec["technique_id"],
            "technique_name": rec["technique_name"],
            "matched_terms": sorted(list(rec["matched_terms"])),
            "score": score,
            "confidence": round(confidence, 2),
        })

    # sort highest score first
    out.sort(key=lambda x: x["score"], reverse=True)
    return out

