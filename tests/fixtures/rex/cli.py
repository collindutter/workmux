#!/usr/bin/env python3

import json
import os
import subprocess
import sys
from pathlib import Path

args = sys.argv[1:]
if "client" in args and "ls" in args:
    count = int(os.environ.get("WORKMUX_TEST_APP_COUNT", "1"))
    print(
        json.dumps(
            {
                "clients": [
                    {"client_id": f"app:{i}", "info": {"kind": "app"}}
                    for i in range(count)
                ]
                + [{"client_id": "cli", "info": {"kind": "cli"}}]
            }
        )
    )
    sys.exit(0)

if "do" in args and "session.select" in args:
    selection = json.loads(args[args.index("--args") + 1])
    selection["client"] = args[args.index("--client") + 1]
    with open(os.environ["WORKMUX_TEST_APP_LOG"], "a") as log:
        log.write(json.dumps(selection) + "\n")
    print("null")
    sys.exit(0)

real_rex = os.environ["WORKMUX_TEST_REAL_REX"]
fault_path = os.environ.get("WORKMUX_TEST_REX_FAULT")
if fault_path and Path(fault_path).exists() and "call" in args:
    index = args.index("call")
    method = args[index + 1]
    params = json.loads(args[index + 2])
    fault = json.loads(Path(fault_path).read_text())
    if method == fault["method"] and all(
        params.get(key) == fault[key]
        for key in ("session_id", "block_id")
        if key in fault
    ):
        Path(fault_path).rename(fault_path + ".triggered")
        action = fault["action"]
        if action in ("close-block", "close-session"):
            server = args[args.index("--server") + 1]
            target = (
                ["block", "close", "-s", params["session_id"], params["block_id"]]
                if action == "close-block"
                else ["kill", params["session_id"]]
            )
            subprocess.run(
                [real_rex, "--autostart=false", "--server", server, *target],
                check=True,
                capture_output=True,
                timeout=10,
            )
        elif action == "transport":
            args[args.index("--server") + 1] = fault["server"]
        else:
            print(
                {
                    "malformed": "{",
                    "invalid-process": "{}",
                    "unavailable": '{"last_exit":null}',
                    "false-not-found": "",
                }[action]
            )
            if action == "false-not-found":
                print(
                    'Error: stream response "control-2" failed: block not found: '
                    f"{params['block_id']} (status=404 code=not_found)",
                    file=sys.stderr,
                )
                sys.exit(3)
            sys.exit(0)

os.execv(real_rex, ["rex", *args])
