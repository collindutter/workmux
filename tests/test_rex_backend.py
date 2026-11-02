import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

from .conftest import poll_until, setup_git_repo

pytestmark = pytest.mark.skipif(
    os.environ.get("WORKMUX_TEST_REX") != "1" or shutil.which("rex") is None,
    reason="requires Rex and WORKMUX_TEST_REX=1",
)


class RexProject:
    def __init__(self, root: Path, binary: Path, socket_dir: Path, config_text=""):
        self.repo = root / "repo with spaces"
        self.repo.mkdir()
        self.binary = binary
        self.server = f"unix://{socket_dir}/rex.sock"
        self.env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(
                ("REX_", "TMUX", "WEZTERM_", "ZELLIJ", "KITTY_", "WORKMUX_", "GIT_")
            )
        }
        self.env.update(
            REX_SERVER=self.server,
            SHELL="/bin/bash",
            XDG_CONFIG_HOME=str(root / "config"),
            XDG_STATE_HOME=str(root / "state"),
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_CONFIG_NOSYSTEM="1",
        )
        setup_git_repo(self.repo, self.env)
        config = root / "rex.lua"
        config.write_text(config_text)
        self.rex(
            "server",
            "start",
            "--state-dir",
            str(root / "rex-state"),
            "--config",
            str(config),
            "--env",
            "SHELL=/bin/bash",
            "--json",
        )

    def command(self, args, **kwargs):
        return subprocess.run(
            args,
            cwd=self.repo,
            env=self.env,
            text=True,
            capture_output=True,
            check=True,
            timeout=45,
            **kwargs,
        ).stdout

    def rex(self, *args):
        return self.command(["rex", "-S", self.server, "--autostart=false", *args])

    def wm(self, *args, **kwargs):
        return self.command([str(self.binary), *args], **kwargs)

    def new_session(self, label, cwd=None):
        return json.loads(
            self.rex(
                "new",
                label,
                "-c",
                str(cwd or self.repo),
                "--json",
                "--shell=none",
                "--",
                "/bin/bash",
                "--noprofile",
                "--norc",
            )
        )

    def view(self, session=None):
        return json.loads(
            self.rex(
                "session",
                "inspect",
                session or self.env["REX_SESSION"],
                "--json",
            )
        )

    def configure(self, panes):
        (self.repo / ".workmux.yaml").write_text(
            yaml.safe_dump(
                {
                    "nerdfont": False,
                    "panes": panes,
                    "pre_remove": [],
                }
            )
        )
        self.command(["git", "add", ".workmux.yaml"])
        self.command(["git", "commit", "-m", "test: configure panes"])

    def window(self, label):
        return next(w for w in self.view()["windows"] if w["label"] == label)


@pytest.fixture
def rex_project(tmp_path, workmux_exe_path, request):
    # macOS Unix sockets cannot use pytest's full temporary directory path.
    with tempfile.TemporaryDirectory(prefix="wm-rex-", dir="/tmp") as directory:
        project = RexProject(
            tmp_path, workmux_exe_path, Path(directory), getattr(request, "param", "")
        )
        try:
            created = project.new_session("workmux-test")
            project.env.update(
                REX_SESSION=created["session_id"],
                REX_BLOCK=created["initial_windows"][0]["block_ids"][0],
            )
            yield project
        finally:
            project.rex("server", "stop")


@pytest.fixture
def rex_app(rex_project, tmp_path):
    p = rex_project
    cli_dir = tmp_path / "bin"
    cli_dir.mkdir()
    wrapper = cli_dir / "rex"
    shutil.copyfile(Path(__file__).parent / "fixtures/rex/cli.py", wrapper)
    wrapper.chmod(0o755)
    log = tmp_path / "app-selections.jsonl"
    p.env.update(
        WORKMUX_TEST_REAL_REX=shutil.which("rex"),
        WORKMUX_TEST_APP_LOG=str(log),
        PATH=f"{cli_dir}{os.pathsep}{p.env['PATH']}",
    )
    return log


@pytest.mark.parametrize(
    "rex_project",
    [
        (
            'rex.bind("g", function() return true end)\n'
            'rex.bind("ctrl+x", function() return true end)\n'
        )
    ],
    indirect=True,
)
def test_rex_key_events_bypass_bindings(rex_project):
    p = rex_project
    env = p.env | {
        "WORKMUX_REX_TEST_SERVER": p.server,
        "REX_BLOCK": "stale-block",
        "REX_WINDOW": "stale-window",
        "REX_CLIENT": "stale-client",
    }
    result = subprocess.run(
        [
            "cargo",
            "test",
            "--manifest-path",
            str(Path(__file__).resolve().parents[1] / "Cargo.toml"),
            "--bin",
            "workmux",
            "multiplexer::rex::tests::live_key_events_on_isolated_server",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
        ],
        cwd=p.repo,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 passed" in result.stdout


def test_rex_program_status_requires_terminal_output(rex_project, tmp_path):
    p = rex_project
    received = tmp_path / "terminal-input"
    reader = (
        "import os,sys,tty\n"
        "tty.setraw(0)\n"
        "with open(sys.argv[1], 'wb', buffering=0) as f:\n"
        " print('\\x1b]7501;state=working:id=output:app=workmux-audit\\x1b\\\\', "
        "end='', flush=True)\n"
        " while True: f.write(os.read(0, 1024))\n"
    )
    created = json.loads(
        p.rex(
            "run",
            "-s",
            p.env["REX_SESSION"],
            "--focus=false",
            "--json",
            "--shell=none",
            "--",
            "python3",
            "-c",
            reader,
            str(received),
        )
    )
    block = created["block_ids"][0]

    def records():
        return json.loads(
            p.rex(
                "block",
                "call",
                "-s",
                p.env["REX_SESSION"],
                "-b",
                block,
                "program_status",
            )
        )["records"]

    assert poll_until(lambda: len(records()) == 1, timeout=10)
    assert records()[0]["state"] == "working"
    assert records()[0]["id"] == "output"
    # `write` is input: it cannot deliver OSC output to the terminal emulator.
    sequence = "\x1b]7501;state=done:id=input\x1b\\"
    p.rex(
        "block",
        "call",
        "-s",
        p.env["REX_SESSION"],
        "-b",
        block,
        "write",
        json.dumps({"data": sequence}),
    )
    assert poll_until(
        lambda: received.exists() and received.read_bytes() == sequence.encode(),
        timeout=10,
    )
    assert [(r["id"], r["state"]) for r in records()] == [("output", "working")]


def test_rex_add_and_open_select_the_app_window(rex_project, rex_app):
    p = rex_project
    p.configure([{}])
    p.wm("add", "background", "--background")
    assert not rex_app.exists()
    p.wm("add", "foreground")
    selections = [json.loads(line) for line in rex_app.read_text().splitlines()]
    assert selections[-1] == {
        "client": "app:0",
        "session_id": p.env["REX_SESSION"],
        "window_id": p.window("wm-foreground")["window_id"],
    }
    p.wm("open", "background")
    selection = json.loads(rex_app.read_text().splitlines()[-1])
    assert selection["window_id"] == p.window("wm-background")["window_id"]


def test_rex_multiple_apps_require_an_explicit_client(rex_project, rex_app):
    p = rex_project
    p.configure([{}])
    p.env["WORKMUX_TEST_APP_COUNT"] = "2"
    p.wm("add", "background", "--background")
    with pytest.raises(subprocess.CalledProcessError) as error:
        p.wm("open", "background")
    assert "REX_CLIENT" in error.value.stderr
    assert not rex_app.exists()
    p.env["REX_CLIENT"] = "my laptop"
    p.wm("open", "background")
    assert json.loads(rex_app.read_text().splitlines()[-1])["client"] == "my laptop"


def test_rex_dashboard_displays_agents_and_jumps_across_sessions(rex_project, rex_app):
    p = rex_project
    p.configure([{}])
    origin_session = p.env["REX_SESSION"]
    origin_block = p.env["REX_BLOCK"]
    foreign = p.new_session("agents")
    p.env.update(
        REX_SESSION=foreign["session_id"],
        REX_BLOCK=foreign["initial_windows"][0]["block_ids"][0],
    )
    p.wm("add", "tracked", "--background")
    window = p.window("wm-tracked")
    p.env["REX_BLOCK"] = window["layers"][0]["blocks"][0]["block_id"]
    p.wm("register-agent", input="")
    p.wm("set-window-status", "working", input="")
    p.env.update(REX_SESSION=origin_session, REX_BLOCK=origin_block)
    forwarded = [
        f"{key}={p.env[key]}"
        for key in (
            "PATH",
            "SHELL",
            "XDG_CONFIG_HOME",
            "XDG_STATE_HOME",
            "WORKMUX_TEST_REAL_REX",
            "WORKMUX_TEST_APP_LOG",
        )
    ]
    dashboard = json.loads(
        p.rex(
            "run",
            "-s",
            origin_session,
            "-c",
            str(p.repo),
            "--focus=false",
            "--keep-open",
            "--json",
            "--shell=none",
            "--",
            "env",
            *forwarded,
            str(p.binary),
            "dashboard",
        )
    )["block_ids"][0]

    def capture():
        return p.rex("capture", "-s", origin_session, "-b", dashboard, "--trim")

    assert poll_until(lambda: "tracked" in capture(), timeout=10), capture()
    p.rex("send-key", "-s", origin_session, "-b", dashboard, "enter")
    assert poll_until(rex_app.exists, timeout=10), capture()
    selection = json.loads(rex_app.read_text().splitlines()[-1])
    assert selection == {
        "client": "app:0",
        "session_id": foreign["session_id"],
        "window_id": window["window_id"],
    }


def test_rex_worktree_lifecycle_preserves_other_sessions(rex_project):
    p = rex_project
    p.configure([{}, {"split": "horizontal", "percentage": 40}])
    original = p.view()["active_window_id"]
    other = p.new_session("unrelated")
    p.rex(
        "window",
        "new",
        "-s",
        other["session_id"],
        "wm-feature",
        "--json",
        "--shell=none",
        "--",
        "/bin/bash",
        "--noprofile",
        "--norc",
    )
    other_before = p.view(other["session_id"])

    p.wm("add", "feature", "--background")
    window = p.window("wm-feature")
    assert p.view()["active_window_id"] == original
    assert sum(len(layer["blocks"]) for layer in window["layers"]) == 2
    assert window["layers"][0]["layout"]["split"]["ratio"] == pytest.approx(0.6)
    worktree = Path(p.wm("path", "feature").strip())
    assert worktree.is_dir()
    listed = json.loads(p.wm("list", "--json"))
    assert next(w for w in listed if w["handle"] == "feature")["is_open"]

    p.wm("rename", "feature", "renamed")
    assert p.window("wm-renamed")["window_id"] == window["window_id"]
    p.wm("close", "renamed")
    assert all(w["label"] != "wm-renamed" for w in p.view()["windows"])
    assert Path(p.wm("path", "renamed").strip()).is_dir()
    p.wm("open", "renamed")
    p.window("wm-renamed")
    p.wm("remove", "renamed", "--force")
    assert all(w["label"] != "wm-renamed" for w in p.view()["windows"])
    other_after = p.view(other["session_id"])
    for key in ("revision", "label", "active_window_id", "windows"):
        assert other_after[key] == other_before[key]


def test_rex_commands_status_and_capture(rex_project):
    p = rex_project
    p.configure([{"command": "printf 'rex-ready\\n'", "focus": True}])
    p.wm("add", "commands", "--background")
    window = p.window("wm-commands")
    block = window["layers"][0]["blocks"][0]["block_id"]

    def capture():
        return p.rex("capture", "-s", p.env["REX_SESSION"], "-b", block, "--trim")

    assert poll_until(lambda: "rex-ready" in capture().splitlines(), timeout=10)
    # The explicit identity must work even with stale inherited pane variables.
    p.env.update(
        WORKMUX_STATUS_BACKEND="rex",
        WORKMUX_STATUS_INSTANCE=p.server,
        WORKMUX_STATUS_PANE_ID=block,
    )
    p.wm("register-agent", input="")
    p.wm("set-window-status", "working", input='{"prompt":"rex prompt"}')
    status = json.loads(p.wm("status", "commands", "--json"))
    assert len(status["agents"]) == 1
    assert status["agents"][0]["status"] == "working"
    assert "rex-ready" in p.wm("capture", "commands")
    p.wm("send", "commands", "printf 'sent-by-workmux\\n'")
    assert poll_until(lambda: "sent-by-workmux" in capture().splitlines(), timeout=10)
    assert "run-by-workmux" in p.wm(
        "run", "commands", "--timeout", "10", "--", "printf", "run-by-workmux\\n"
    )
    p.wm("set-window-status", "done", input="")
    p.wm("wait", "commands", "--status", "done", "--timeout", "5")
    assert (
        json.loads(p.wm("status", "commands", "--json"))["agents"][0]["status"]
        == "done"
    )


@pytest.mark.parametrize("shell", ["bash", "fish"])
def test_rex_agent_receives_replacement_block_identity(rex_project, shell):
    shell_path = shutil.which(shell)
    if shell_path is None:
        pytest.skip(f"{shell} is not installed")
    p = rex_project
    p.env["SHELL"] = shell_path
    script = p.repo / "record-agent"
    script.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$WORKMUX_STATUS_BACKEND" "$WORKMUX_STATUS_INSTANCE" '
        '"$WORKMUX_STATUS_PANE_ID" "$REX_BLOCK" > .identity\n'
    )
    script.chmod(0o755)
    p.command(["git", "add", "record-agent"])
    global_config = Path(p.env["XDG_CONFIG_HOME"]) / "workmux" / "config.yaml"
    global_config.parent.mkdir(parents=True)
    global_config.write_text(
        yaml.safe_dump(
            {"agents": {"probe": {"command": "./record-agent", "type": "pi"}}}
        )
    )
    p.configure(
        [
            {"command": "printf 'editor-ready\\n'", "focus": True},
            {"command": "<agent:probe>", "split": "horizontal", "percentage": 50},
        ],
    )
    p.wm("add", "identity", "--background")
    worktree = Path(p.wm("path", "identity").strip())
    identity = worktree / ".identity"
    assert poll_until(lambda: identity.exists(), timeout=10), [
        p.rex("capture", "-s", p.env["REX_SESSION"], "-b", block["block_id"], "--trim")
        for block in p.window("wm-identity")["layers"][0]["blocks"]
    ]
    backend, server, target, inherited = identity.read_text().splitlines()
    assert backend == "rex"
    assert server == p.server
    assert target == inherited
    assert target != p.env["REX_BLOCK"]
    blocks = p.window("wm-identity")["layers"][0]["blocks"]
    assert target in {block["block_id"] for block in blocks}


def test_rex_session_mode_fails_before_creating_worktree(rex_project):
    p = rex_project
    p.configure([{}])
    with pytest.raises(subprocess.CalledProcessError, match="returned non-zero"):
        p.wm("add", "unsupported-session", "--session")
    assert "unsupported-session" not in p.command(["git", "branch", "--list"])
    assert len(p.view()["windows"]) == 1


def test_rex_removal_from_its_own_worktree(rex_project):
    p = rex_project
    p.configure([{}])
    p.wm("add", "self-remove", "--background")
    window = p.window("wm-self-remove")
    worktree = Path(p.wm("path", "self-remove").strip())
    p.env["REX_BLOCK"] = window["layers"][0]["blocks"][0]["block_id"]
    main_repo = p.repo
    p.repo = worktree
    try:
        p.wm("remove", "--force")
    finally:
        p.repo = main_repo
    assert poll_until(lambda: not worktree.exists(), timeout=10)
    assert poll_until(
        lambda: all(w["window_id"] != window["window_id"] for w in p.view()["windows"]),
        timeout=10,
    )


def register_observation_agent(p, block):
    p.env.update(
        WORKMUX_STATUS_BACKEND="rex",
        WORKMUX_STATUS_INSTANCE=p.server,
        WORKMUX_STATUS_PANE_ID=block,
    )
    p.wm("register-agent", input="")
    p.wm("set-window-status", "working", input="")


def observation_records(p):
    directory = Path(p.env["XDG_STATE_HOME"]) / "workmux" / "agents"
    return {
        json.loads(path.read_text())["pane_key"]["pane_id"]: path.read_bytes()
        for path in directory.glob("*.json")
    }


def observation_pair(p):
    p.configure([{}])
    p.wm("add", "observed", "--background")
    peer = p.window("wm-observed")["layers"][0]["blocks"][0]["block_id"]
    register_observation_agent(p, peer)
    worktree = Path(p.wm("path", "observed").strip())
    foreign = p.new_session("doomed", cwd=worktree)
    victim = foreign["initial_windows"][0]["block_ids"][0]
    register_observation_agent(p, victim)
    assert set(observation_records(p)) == {peer, victim}
    return peer, victim, foreign["session_id"]


def observation_fault(p, tmp_path, method, session, action, block=None, process=None):
    path = tmp_path / "rex-fault.json"
    fault = {"method": method, "session_id": session, "action": action}
    if block is not None:
        fault["block_id"] = block
    if process is not None:
        fault["process"] = process
    if action == "transport":
        fault["server"] = p.server.replace("rex.sock", "missing.sock")
    path.write_text(json.dumps(fault))
    p.env["WORKMUX_TEST_REX_FAULT"] = str(path)
    return path.with_suffix(".json.triggered")


def test_rex_kept_open_exit_prunes_agent_and_preserves_peer(rex_project):
    p = rex_project
    p.configure([{}])
    p.wm("add", "observed", "--background")
    peer = p.window("wm-observed")["layers"][0]["blocks"][0]["block_id"]
    register_observation_agent(p, peer)
    victim = json.loads(
        p.rex(
            "run",
            "-s",
            p.env["REX_SESSION"],
            "-b",
            peer,
            "--split=right",
            "-c",
            p.wm("path", "observed").strip(),
            "--keep-open",
            "--focus=false",
            "--json",
            "--shell=none",
            "--",
            "/bin/bash",
            "--noprofile",
            "--norc",
        )
    )["block_ids"][0]
    register_observation_agent(p, victim)
    before = observation_records(p)
    p.rex("send", "-s", p.env["REX_SESSION"], "-b", victim, "exit")
    p.rex("send-key", "-s", p.env["REX_SESSION"], "-b", victim, "enter")

    def exited():
        return (
            json.loads(
                p.rex(
                    "block", "call", "-s", p.env["REX_SESSION"], "-b", victim, "process"
                )
            )["last_exit"]
            is not None
        )

    assert poll_until(exited, timeout=10)
    # The explicit status target queries the individual pane before any bulk scan.
    p.wm("set-window-status", "done", input="")
    assert observation_records(p) == before
    status = json.loads(p.wm("status", "observed", "--json"))
    assert {a["pane_id"] for a in status["agents"]} == {peer}
    # Status is read-only; project discovery runs pruning reconciliation and its
    # validate_agent_alive fallback for panes omitted from the bulk snapshot.
    p.wm("list", "--all", "--json")
    assert set(observation_records(p)) == {peer}
    assert exited()  # Reconciliation did not close the retained terminal.


OBSERVATION_RACES = [
    ("session.view", "close-session"),
    ("session.list_blocks", "close-session"),
    ("com.superlogical.terminal.process", "close-session"),
    ("com.superlogical.terminal.title", "close-session"),
    ("com.superlogical.terminal.process", "close-block"),
    ("com.superlogical.terminal.title", "close-block"),
]


@pytest.mark.parametrize("method,action", OBSERVATION_RACES)
@pytest.mark.parametrize("individual", [False, True], ids=["bulk", "individual"])
def test_rex_observation_closure_preserves_survivor(
    rex_project, rex_app, tmp_path, method, action, individual
):
    p = rex_project
    peer, victim, session = observation_pair(p)
    before = observation_records(p)
    triggered = observation_fault(
        p,
        tmp_path,
        method,
        session,
        action,
        block=victim if method.startswith("com.") else None,
    )
    if individual:
        p.wm("set-window-status", "done", input="")
        assert triggered.exists()
        assert observation_records(p) == before
    p.wm("list", "--all", "--json")
    assert triggered.exists()
    status = json.loads(p.wm("status", "observed", "--json"))
    assert {a["pane_id"] for a in status["agents"]} == {peer}
    assert set(observation_records(p)) == {peer}


@pytest.mark.parametrize(
    "method",
    [
        "session.view",
        "session.list_blocks",
        "com.superlogical.terminal.process",
        "com.superlogical.terminal.title",
    ],
)
@pytest.mark.parametrize("action", ["malformed", "transport"])
def test_rex_observation_failure_propagates_without_pruning(
    rex_project, rex_app, tmp_path, method, action
):
    p = rex_project
    peer, victim, session = observation_pair(p)
    before = observation_records(p)
    triggered = observation_fault(
        p,
        tmp_path,
        method,
        session,
        action,
        block=victim if method.startswith("com.") else None,
    )
    with pytest.raises(subprocess.CalledProcessError) as error:
        p.wm("status", "observed", "--json")
    assert triggered.exists()
    expected = "parse Rex JSON" if action == "malformed" else "failed"
    assert expected in error.value.stderr
    assert observation_records(p) == before
    observation_fault(
        p,
        tmp_path,
        method,
        session,
        action,
        block=victim if method.startswith("com.") else None,
    )
    with pytest.raises(subprocess.CalledProcessError):
        p.wm("list", "--all", "--json")
    assert observation_records(p) == before
    status = json.loads(p.wm("status", "observed", "--json"))
    assert {a["pane_id"] for a in status["agents"]} == {peer, victim}


@pytest.mark.parametrize(
    "action", ["unavailable", "invalid-process", "false-not-found"]
)
def test_rex_process_observation_requires_proof_of_exit(
    rex_project, rex_app, tmp_path, action
):
    p = rex_project
    peer, victim, session = observation_pair(p)
    before = observation_records(p)
    triggered = observation_fault(
        p, tmp_path, "com.superlogical.terminal.process", session, action, block=victim
    )
    if action == "unavailable":
        status = json.loads(p.wm("status", "observed", "--json"))
        assert {a["pane_id"] for a in status["agents"]} == {peer, victim}
    else:
        with pytest.raises(subprocess.CalledProcessError):
            p.wm("status", "observed", "--json")
    assert triggered.exists()
    assert observation_records(p) == before


@pytest.mark.parametrize(
    "process",
    [
        pytest.param(None, id="unavailable"),
        pytest.param(
            {
                "last_exit": None,
                "foreground": {"pid": 12, "name": "bash", "cwd": "/tmp"},
            },
            id="missing-child",
        ),
        pytest.param(
            {"last_exit": None, "child": {"pid": 12, "name": "bash", "cwd": "/tmp"}},
            id="missing-foreground",
        ),
        pytest.param(
            {
                "last_exit": None,
                "child": {"pid": 12, "name": "bash"},
                "foreground": {"pid": 12, "name": "bash"},
            },
            id="missing-cwd",
        ),
    ],
)
def test_rex_status_hook_preserves_record_with_incomplete_process_snapshot(
    rex_project, rex_app, tmp_path, process
):
    p = rex_project
    peer, victim, session = observation_pair(p)
    before = observation_records(p)
    for key in (
        "WORKMUX_STATUS_BACKEND",
        "WORKMUX_STATUS_INSTANCE",
        "WORKMUX_STATUS_PANE_ID",
    ):
        p.env.pop(key)
    p.env.update(REX_SESSION=session, REX_BLOCK=victim)
    triggered = observation_fault(
        p,
        tmp_path,
        "com.superlogical.terminal.process",
        session,
        "unavailable" if process is None else "process-response",
        block=victim,
        process=process,
    )
    p.wm("set-window-status", "working", input="")
    assert triggered.exists()
    assert observation_records(p) == before
    status = json.loads(p.wm("status", "observed", "--json"))
    assert {agent["pane_id"] for agent in status["agents"]} == {peer, victim}
    p.wm("list", "--all", "--json")
    assert observation_records(p) == before
