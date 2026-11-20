# -*- coding: utf-8 -*-
"""无界面运行器：GitHub Actions 或 Windows 计划任务使用。"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from pathlib import Path

import app


def load_config(path: Path) -> dict:
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def main() -> int:
    parser = argparse.ArgumentParser(description="节点捕食者 Pro 无界面运行器")
    parser.add_argument("--config", default="config.json", help="配置文件路径")
    parser.add_argument("--max-nodes", type=int, default=None, help="覆盖最大保留节点数")
    parser.add_argument("--output-dir", default=None, help="覆盖输出目录")
    args = parser.parse_args()

    base = Path(__file__).resolve().parent
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = base / config_path
    raw = load_config(config_path)

    regions = raw.get("regions") or ["ALL"]
    if isinstance(regions, str):
        regions = [item.strip().upper() for item in regions.split(",") if item.strip()]
    else:
        regions = [str(item).strip().upper() for item in regions]
    if "ALL" in regions or not regions:
        selected_regions = set(app.REGION_BY_CODE)
    else:
        selected_regions = {code for code in regions if code in app.REGION_BY_CODE}

    output_dir = Path(args.output_dir or raw.get("output_dir") or "output")
    if not output_dir.is_absolute():
        output_dir = base / output_dir

    cfg = app.RunConfig(
        latency_limit_ms=max(100, int(raw.get("latency_limit_ms", 800))),
        quality_mode=str(raw.get("quality_mode", "balanced")),
        jitter_limit_ms=max(30, int(raw.get("jitter_limit_ms", 220))),
        max_workers=max(10, min(300, int(raw.get("max_workers", 120)))),
        max_nodes=max(0, int(args.max_nodes if args.max_nodes is not None else raw.get("max_nodes", 300))),
        selected_regions=selected_regions,
        keep_unknown_region=bool(raw.get("keep_unknown_region", False)),
        output_dir=output_dir,
    )
    if cfg.quality_mode not in app.QUALITY_PRESETS:
        cfg.quality_mode = "balanced"

    cancel = threading.Event()
    exit_code = {"value": 1}
    last_percent = {"value": -10}

    def emit(event: dict) -> None:
        event_type = event.get("type")
        stamp = time.strftime("%H:%M:%S")
        if event_type == "log":
            print(f"[{stamp}] {event.get('text')}", flush=True)
        elif event_type == "progress":
            pct = int(float(event.get("value", 0)))
            if pct >= last_percent["value"] + 5 or pct >= 100:
                last_percent["value"] = pct
                print(f"[{stamp}] {pct}% {event.get('status', '')}", flush=True)
        elif event_type == "done":
            exit_code["value"] = 0
            print(f"[{stamp}] DONE count={event.get('count')} links={event.get('link_count')}", flush=True)
            for key in ("txt", "plain", "yaml", "singbox"):
                print(f"  {key}: {event.get(key)}", flush=True)
        elif event_type == "error":
            print(f"[{stamp}] ERROR {event.get('text')}", flush=True)
            trace = event.get("traceback")
            if trace:
                print(trace, file=sys.stderr, flush=True)
        elif event_type == "cancelled":
            print(f"[{stamp}] CANCELLED", flush=True)

    started = time.time()
    print(f"节点捕食者 Pro 无界面运行 · {time.strftime('%Y-%m-%d %H:%M:%S')}", flush=True)
    print(f"配置：延迟<={cfg.latency_limit_ms}ms，{app.QUALITY_PRESETS[cfg.quality_mode]['label']}，"
          f"最多{cfg.max_nodes}个，地区{len(selected_regions)}个", flush=True)
    app.run_pipeline(cfg, emit, cancel)
    print(f"耗时 {time.time() - started:.1f}s", flush=True)
    return exit_code["value"]


if __name__ == "__main__":
    raise SystemExit(main())
