#!/usr/bin/env python3
"""Generate metrics documentation in README.md from ibc_monitor/metrics.py."""
from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import List, Tuple

from prometheus_client import Gauge

# Ensure project root is on the Python path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def collect_metrics() -> List[Tuple[str, str, Tuple[str, ...]]]:
    module = importlib.import_module("ibc_monitor.metrics")
    metrics: List[Tuple[str, str, Tuple[str, ...]]] = []
    for obj in vars(module).values():
        if isinstance(obj, Gauge):
            metrics.append((obj._name, obj._documentation, obj._labelnames))
    return sorted(metrics, key=lambda m: m[0])


def generate_table(metrics: List[Tuple[str, str, Tuple[str, ...]]]) -> str:
    lines = ["| Metric | Description | Labels |", "|---|---|---|"]
    for name, doc, labels in metrics:
        label_str = ", ".join(labels)
        lines.append(f"| `{name}` | {doc} | {label_str} |")
    return "\n".join(lines)


def main() -> None:
    metrics = collect_metrics()
    table = generate_table(metrics)
    readme = Path("README.md")
    content = readme.read_text()
    start_marker = "<!-- METRICS_START -->"
    end_marker = "<!-- METRICS_END -->"
    start = content.index(start_marker) + len(start_marker)
    end = content.index(end_marker)
    new_content = content[:start] + "\n" + table + "\n" + content[end:]
    readme.write_text(new_content)
    print("README.md updated")


if __name__ == "__main__":
    main()
