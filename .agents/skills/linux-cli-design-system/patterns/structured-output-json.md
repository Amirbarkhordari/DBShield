# Structured Output and JSON Patterns

This document provides reusable implementations for building stable JSON envelopes, newline-delimited JSON (NDJSON) streaming, and verifying output integrity with `jq`.

---

## 1. JSON Envelope Builder

Always wrap tool results in a standard metadata envelope:

```python
"""
json_output.py - Standard envelope builder and serializer
"""
import sys
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

def build_envelope(
    tool_name: str,
    tool_version: str,
    status: str,
    data: Any,
    summary: Optional[Dict[str, Any]] = None,
    errors: Optional[List[Dict[str, str]]] = None,
    schema_version: str = "1.0.0"
) -> Dict[str, Any]:
    """Construct standard top-level JSON response envelope."""
    return {
        "schema_version": schema_version,
        "tool": tool_name,
        "version": tool_version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "data": data,
        "summary": summary or {},
        "errors": errors or []
    }

def print_json(envelope: Dict[str, Any], pretty: bool = True) -> None:
    """Print pure JSON to stdout with no ANSI or banner contamination."""
    indent = 2 if pretty else None
    output = json.dumps(envelope, indent=indent, default=str)
    # Write directly to stdout payload stream
    sys.stdout.write(output + "\n")
    sys.stdout.flush()
```

---

## 2. Streaming NDJSON (Newline-Delimited JSON)

For streaming operations (e.g. packet sniffers, tailing logs, live scan monitors), emit one valid JSON object per line on `stdout`:

```python
def stream_ndjson_event(event_type: str, payload: Dict[str, Any]) -> None:
    """Emit a single NDJSON event line."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "type": event_type,
        "payload": payload
    }
    sys.stdout.write(json.dumps(record, default=str) + "\n")
    sys.stdout.flush()
```

### Consumption Example:
```bash
# Downstream tools process events in real time:
tool monitor --format ndjson | jq --unbuffered '.payload | select(.severity == "CRITICAL")'
```

---

## 3. Automated `jq` Quality Verification

When testing JSON output in CI or shell scripts, verify that stdout is parseable:

```bash
# 1. Test standard payload structure
python3 -m mytool scan --target 127.0.0.1 --json > /tmp/out.json
jq -e '.status == "success"' /tmp/out.json > /dev/null || {
    echo "[-] FAILED: JSON status is not 'success'" >&2
    exit 1
}

# 2. Verify no banner contamination leaks into piped stdout
PIPE_RESULT=$(python3 -m mytool scan --target 127.0.0.1 --json | jq -r '.data | keys | length')
if [[ "$PIPE_RESULT" -lt 1 ]]; then
    echo "[-] FAILED: stdout was contaminated with non-JSON text" >&2
    exit 1
fi
```
