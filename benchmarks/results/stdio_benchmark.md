# stdio benchmark

Command: `PYTHONPATH=src python benchmarks/bench_stdio.py`  
rawmcp 0.1.0, Python 3.13.2, Windows-11, 12 logical CPUs. CPU calibration loop: 662.3 ms before, 860.0 ms after (higher means a busier machine).

## Latency (one request in flight)

| Scenario | n | p50 ms | p95 ms | p99 ms | mean ms |
|---|---:|---:|---:|---:|---:|
| rawmcp · calculate (2026-07-28) | 2000 | 1.077 | 1.287 | 2.115 | 1.169 |
| rawmcp · tools/list (2026-07-28) | 800 | 1.372 | 1.498 | 2.123 | 1.41 |
| rawmcp · read_file (2026-07-28) | 800 | 2.762 | 3.589 | 4.984 | 2.881 |
| rawmcp · sqlite_query join (2026-07-28) | 800 | 4.996 | 10.097 | 17.376 | 5.889 |
| rawmcp · run_python sandbox (2026-07-28) | 20 | 305.154 | 389.574 | 422.531 | 317.632 |
| rawmcp · calculate (2025-11-25 session) | 2000 | 1.058 | 1.288 | 1.414 | 1.076 |
| official SDK server · calculate (2026-07-28) | 2000 | 4.022 | 7.757 | 18.485 | 4.748 |
| official SDK server · calculate (2025-11-25 session) | 2000 | 3.691 | 5.182 | 7.484 | 3.902 |

## Throughput (`calculate`, pipelined)

| Server · in-flight window | calls/s |
|---|---:|
| rawmcp · window 1 | 851.9 |
| rawmcp · window 4 | 822.2 |
| rawmcp · window 16 | 631.2 |
| rawmcp · window 64 | 1154.7 |
| official SDK server · window 1 | 201.8 |
| official SDK server · window 4 | 188.4 |
| official SDK server · window 16 | 116.4 |
| official SDK server · window 64 | 118.9 |

Baseline: official MCP Python SDK 2.3.0 `MCPServer` running the same `evaluate()` function (`benchmarks/sdk_baseline_server.py`).
