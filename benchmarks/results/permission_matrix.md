# Permission matrix

Command: `PYTHONPATH=src python benchmarks/permission_matrix.py`

Profiles from `examples/policy.yaml`; `anonymous` is a caller whose token matches no profile.

| Tool | Required scopes | anonymous | reader | analyst | maintainer |
|---|---|---|---|---|---|
| `calculate` | (none) | ⛔ deny | ✅ allow | ✅ allow | ✅ allow |
| `list_dir` | fs:read | ⛔ deny | ✅ allow | ✅ allow | ✅ allow |
| `read_file` | fs:read | ⛔ deny | ✅ allow | ✅ allow | ✅ allow |
| `search_files` | fs:read | ⛔ deny | ✅ allow | ✅ allow | ✅ allow |
| `sqlite_query` | db:read | ⛔ deny | ✅ allow | ✅ allow | ✅ allow |
| `fetch_url` | net:fetch | ⛔ deny | ⛔ deny | ✅ allow | ✅ allow |
| `run_python` | exec:python | ⛔ deny | ⛔ deny | ✅ allow | ✅ allow |
| `write_file` | fs:write | ⛔ deny | ⛔ deny | ⛔ deny | ✅ allow |

## Attack scenarios

| Scenario | Tool | Outcome | Server message |
|---|---|---|---|
| path traversal `../outside.txt` | `read_file` | deny | path '../outside.txt' resolves outside the workspace |
| absolute path `/etc/passwd` | `read_file` | deny | absolute paths are not allowed; use a path relative to the workspace |
| Windows drive path `C:\Windows\win.ini` | `read_file` | deny | absolute paths are not allowed; use a path relative to the workspace |
| symlink to a file outside the workspace | `read_file` | not run (symlinks need privileges on this OS) |  |
| write outside via `../escape.txt` | `write_file` | deny | path '../escape.txt' resolves outside the workspace |
| `DROP TABLE orders` | `sqlite_query` | deny | the database is read-only for this tool: not authorized |
| `ATTACH DATABASE` another file | `sqlite_query` | deny | the database is read-only for this tool: not authorized |
| runaway recursive CTE | `sqlite_query` | error | query exceeded the 2 s time limit or was cancelled |
| domain not on the allowlist | `fetch_url` | deny | domain 'attacker.net' is not on the allowlist |
| plain `http://` | `fetch_url` | deny | scheme 'http' is not allowed; use https |
| allowlisted name resolving to 169.254.169.254 | `fetch_url` | deny | 'metadata.python.org' resolves to a non-public address (169.254.169.254); refusing to connect |
| redirect from allowlisted host to another domain | `fetch_url` | deny | domain 'attacker.net' is not on the allowlist |
| `import socket` | `run_python` | ran, exit 1 | ImportError: module 'socket' is blocked in the sandbox |
| read a file outside the sandbox | `run_python` | ran, exit 1 | PermissionError: file access outside the sandbox is blocked |
| read the parent's environment | `run_python` | ran, exit 0 | not visible |
| spawn a process with `os.system` | `run_python` | ran, exit 1 | PermissionError: os.system is blocked in the sandbox |
| infinite loop | `run_python` | ran, killed (timeout) |  |
| print flood | `run_python` | ran, killed (output limit) | stdout kept 65536 bytes |
| code injection `__import__('os')` | `calculate` | error | unknown function; allowed: abs, acos, asin, atan, atan2, ceil, cos, degrees, exp, factorial, floor, hypot, log |
| huge power `9**9**9` | `calculate` | error | power would exceed 4096 bits |
| wrong argument type (42) | `calculate` | invalid | Invalid arguments for calculate: - expression: Input should be a valid string |
| 4 calls under a 3/minute limit | `read_file` | allow → allow → allow → deny |  |

Every call above was written to the JSONL audit log (56 lines).
