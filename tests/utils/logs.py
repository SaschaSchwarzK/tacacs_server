import json
from typing import Any


def parse_json_lines(text: str) -> list[dict[str, Any]]:
    """Parse JSON objects embedded line-by-line in a log blob.

    Returns a list of dicts for lines that are valid JSON objects; ignores others.
    Also extracts JSON from 'message' field if present.
    """
    results: list[dict[str, Any]] = []
    if not text:
        return results
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Some logs may already be JSON payloads inside other JSON; try to find the inner object
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                results.append(obj)
                # If this is a structured log with a JSON message, also parse the message
                if "message" in obj and isinstance(obj["message"], str):
                    msg = obj["message"].strip()
                    if msg.startswith("{") and msg.endswith("}"):
                        try:
                            inner_obj = json.loads(msg)
                            if isinstance(inner_obj, dict):
                                results.append(inner_obj)
                        except Exception:
                            pass
                continue
        except Exception:
            pass
        # Fallback: detect {...} substring
        start = line.find("{")
        end = line.rfind("}")
        if start != -1 and end != -1 and end > start:
            snippet = line[start : end + 1]
            try:
                obj = json.loads(snippet)
                if isinstance(obj, dict):
                    results.append(obj)
            except Exception:
                continue
    return results
