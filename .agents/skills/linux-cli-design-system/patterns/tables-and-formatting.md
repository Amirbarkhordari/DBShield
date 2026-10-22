# Table and Formatting Patterns

This document provides reusable implementations and formatting patterns for terminal tables, column truncation, and key-value summary cards.

---

## 1. Table Design Rules

1. **Header Contrast**: Table headers should be uppercase and bolded.
2. **Column Alignment**:
   - Text, hostnames, and identifiers: **Left-aligned**.
   - Numbers, port numbers, latencies, percentages, and counters: **Right-aligned**.
   - Status indicators (`[+] Active`, `[-] Down`): **Left-aligned**.
3. **Width Discipline**: The total table width must not exceed the terminal width (`shutil.get_terminal_size().columns`).
4. **Clean Truncation**: When a cell exceeds its column allotment, truncate with `...` rather than breaking rows into ragged text.

---

## 2. Reusable Python Table Formatter

A lightweight, zero-dependency table renderer that automatically calculates column widths, respects terminal bounds, and applies truncation:

```python
"""
table_formatter.py - Zero-dependency terminal table renderer
"""
import shutil
from typing import List, Dict, Any

def render_table(headers: List[str], rows: List[List[Any]], max_width: int = None) -> str:
    """Render a clean terminal table with borders and width limits."""
    if not rows:
        return "(no results to display)"

    if max_width is None:
        max_width = shutil.get_terminal_size(fallback=(80, 24)).columns

    # Stringify all cells
    str_rows = [[str(cell) for cell in row] for row in rows]
    num_cols = len(headers)

    # Calculate optimal column widths based on content
    col_widths = [len(h) for h in headers]
    for row in str_rows:
        for idx in range(num_cols):
            if idx < len(row):
                col_widths[idx] = max(col_widths[idx], len(row[idx]))

    # Account for separators: "│ " + " │ " * (num_cols - 1) + " │"
    overhead = 4 + (num_cols - 1) * 3
    total_needed = sum(col_widths) + overhead

    # Scale down columns if table exceeds max_width
    if total_needed > max_width:
        excess = total_needed - max_width
        # Shrink the widest column
        widest_idx = col_widths.index(max(col_widths))
        col_widths[widest_idx] = max(10, col_widths[widest_idx] - excess)

    # Formatting helper for cells
    def format_cell(text: str, width: int) -> str:
        if len(text) > width:
            return text[:width - 3] + "..." if width >= 3 else text[:width]
        return text.ljust(width)

    # Box-drawing characters
    top_border = "┌─" + "─┬─".join("─" * w for w in col_widths) + "─┐"
    header_sep = "├─" + "─┼─".join("─" * w for w in col_widths) + "─┤"
    bot_border = "└─" + "─┴─".join("─" * w for w in col_widths) + "─┘"

    lines = [top_border]

    # Header row
    hdr_cells = [format_cell(headers[i], col_widths[i]) for i in range(num_cols)]
    lines.append("│ " + " │ ".join(hdr_cells) + " │")
    lines.append(header_sep)

    # Data rows
    for row in str_rows:
        cells = [format_cell(row[i] if i < len(row) else "", col_widths[i]) for i in range(num_cols)]
        lines.append("│ " + " │ ".join(cells) + " │")

    lines.append(bot_border)
    return "\n".join(lines)
```

---

## 3. Key-Value Record Card Pattern

For detailed views of individual assets, records, or vulnerability reports:

```text
┌────────────────────────────────────────────────────────────────────────┐
│ TARGET RECORD: srv-db-primary.internal                                 │
├────────────────────────────────────────────────────────────────────────┤
│ Hostname:          srv-db-primary.internal                             │
│ IPv4 Address:      10.14.2.85                                          │
│ Environment:       Production (us-east-1)                              │
│ OS Version:        Ubuntu 24.04 LTS (Kernel 6.8.0-31-generic)          │
│ Open Ports:        22/tcp (ssh), 5432/tcp (postgresql)                 │
│ Compliance Status: [+] PASSED (14/14 CIS benchmarks verified)          │
│ Last Scanned:      2026-10-22 08:12:00 UTC                             │
└────────────────────────────────────────────────────────────────────────┘
```

### Python Implementation:
```python
def render_record_card(title: str, fields: Dict[str, Any], width: int = 72) -> str:
    border_top = "┌" + "─" * (width - 2) + "┐"
    border_sep = "├" + "─" * (width - 2) + "┤"
    border_bot = "└" + "─" * (width - 2) + "┘"

    lines = [border_top, f"│ {title.ljust(width - 4)} │", border_sep]

    max_key_len = max(len(k) for k in fields.keys())
    for key, val in fields.items():
        key_str = f"{key}:".ljust(max_key_len + 2)
        val_str = str(val)
        available_val_width = width - 4 - len(key_str)
        if len(val_str) > available_val_width:
            val_str = val_str[:available_val_width - 3] + "..."
        line_content = f"{key_str}{val_str}".ljust(width - 4)
        lines.append(f"│ {line_content} │")

    lines.append(border_bot)
    return "\n".join(lines)
```
