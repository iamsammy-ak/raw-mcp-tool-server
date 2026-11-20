# Fuzz campaign

Command: `PYTHONPATH=src python benchmarks/fuzz_campaign.py --cases 10000 --seed 7`

- cases: 10000 (seed 7), 608.7 cases/s
- server crashes: 0 (the process answered every sentinel and exited cleanly with code 0 at end of input)
- stdout lines that were not valid JSON-RPC: 0
- internal errors (-32603): 0

| Case kind | count |
|---|---:|
| batch | 1015 |
| big | 570 |
| bytes | 1228 |
| deep | 763 |
| json | 1240 |
| mutated | 4019 |
| truncated | 1165 |

| Reply | count |
|---|---:|
| -32022 | 3 |
| -32600 | 4588 |
| -32601 | 162 |
| -32602 | 563 |
| -32700 | 3145 |
| result | 501 |
| result (isError) | 621 |
