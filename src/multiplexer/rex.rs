//! Windows are Rex tabs and blocks are panes; mutations use full session IDs
//! and the resolved server endpoint, never ambient focus.

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use super::agent::shell_quote;
use super::types::*;
use super::{Multiplexer, util};
use crate::config::SplitDirection;

const TERMINAL: &str = "com.superlogical.terminal";

#[derive(Debug, Deserialize)]
struct Identity {
    endpoint: String,
    instance_id: String,
}

#[derive(Debug, Deserialize)]
struct ClientList {
    #[serde(deserialize_with = "nullable")]
    clients: Option<Vec<Client>>,
}

#[derive(Debug, Deserialize)]
struct Client {
    client_id: String,
    info: Option<ClientInfo>,
}

#[derive(Debug, Deserialize)]
struct ClientInfo {
    kind: String,
}

#[derive(Debug, Deserialize)]
struct SessionList {
    #[serde(deserialize_with = "nullable")]
    sessions: Option<Vec<Session>>,
}

#[derive(Debug, Deserialize)]
struct Session {
    session_id: String,
    label: String,
}

#[derive(Debug, Deserialize)]
struct View {
    session_id: String,
    label: String,
    active_window_id: Option<String>,
    windows: Option<Vec<Window>>,
}

#[derive(Debug, Deserialize)]
struct Window {
    window_id: String,
    label: String,
    focused_block_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BlockList {
    #[serde(deserialize_with = "nullable")]
    blocks: Option<Vec<Block>>,
}

#[derive(Debug, Deserialize)]
struct Block {
    block_id: String,
    creator_name: String,
    window_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Created {
    block_ids: Vec<String>,
    window_id: Option<String>,
}

impl Created {
    fn pane_id(&self) -> Result<String> {
        match self.block_ids.as_slice() {
            [id] if !id.is_empty() => Ok(id.clone()),
            _ => bail!("Rex creation did not return exactly one block ID"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct Process {
    pid: u32,
    name: String,
    cwd: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct Processes {
    child: Option<Process>,
    foreground: Option<Process>,
    // Required even when null: an empty/malformed process response must fail.
    #[serde(deserialize_with = "nullable")]
    last_exit: Option<Exit>,
}

#[derive(Debug, Deserialize)]
struct Exit {
    #[serde(rename = "exit_code")]
    _exit_code: i32,
}

#[derive(Debug, Deserialize)]
struct Title {
    title: String,
}

#[derive(Debug, thiserror::Error)]
#[error("rex {command} failed ({status}): {stderr}")]
struct CliFailure {
    command: String,
    status: std::process::ExitStatus,
    stderr: String,
}

impl CliFailure {
    fn resource_missing(&self) -> bool {
        // Rex's CLI exposes API error codes only in its stderr diagnostic.
        self.stderr.ends_with("(status=404 code=session_not_found)")
            || self.stderr.ends_with("(status=404 code=not_found)")
    }
}

/// A backend is pinned to the endpoint returned by Rex on its first successful
/// connection. Only blocks created by this object may be replaced by respawn.
#[derive(Debug, Default)]
pub struct RexBackend {
    server: Option<String>,
    endpoint: OnceLock<String>,
    client: OnceLock<Option<String>>,
    created_blocks: Mutex<HashSet<String>>,
}

impl RexBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn for_server(instance: &str) -> Self {
        Self {
            server: Some(instance.to_owned()),
            ..Self::default()
        }
    }

    fn command_for(server: Option<&str>) -> Command {
        let mut command = Command::new("rex");
        command.args(["--autostart=false", "--color=never"]);
        if let Some(server) = server {
            command.args(["--server", server]);
        }
        // Explicit IDs below supersede all inherited location/client hints.
        for name in ["REX_SESSION", "REX_BLOCK", "REX_WINDOW", "REX_CLIENT"] {
            command.env_remove(name);
        }
        command
    }

    fn output(mut command: Command, args: &[&str]) -> Result<String> {
        let output = command
            .args(args)
            .output()
            .context("Failed to execute rex")?;
        if !output.status.success() {
            return Err(CliFailure {
                command: args.first().copied().unwrap_or("").to_owned(),
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            }
            .into());
        }
        String::from_utf8(output.stdout).context("Rex returned non-UTF-8 output")
    }

    fn endpoint(&self) -> Result<&str> {
        if self.endpoint.get().is_none() {
            let output = Self::output(
                Self::command_for(self.server.as_deref()),
                &["whoami", "--json"],
            )?;
            let identity: Identity = parse(&output)?;
            if identity.endpoint.is_empty() {
                bail!("Rex returned an empty server endpoint");
            }
            let _ = self.endpoint.set(identity.endpoint);
        }
        Ok(self.endpoint.get().expect("endpoint initialized"))
    }

    fn cli(&self, args: &[&str]) -> Result<String> {
        Self::output(Self::command_for(Some(self.endpoint()?)), args)
    }

    fn display_client(&self) -> Result<Option<&str>> {
        if self.client.get().is_none() {
            let explicit = std::env::var("REX_CLIENT").ok().filter(|s| !s.is_empty());
            let client = if explicit.is_some() {
                explicit
            } else {
                let list: ClientList = parse(&self.cli(&["client", "ls", "--json"])?)?;
                choose_app(list.clients.unwrap_or_default())?
            };
            let _ = self.client.set(client);
        }
        Ok(self.client.get().and_then(|client| client.as_deref()))
    }

    fn display_window(&self, session: &str, window: &str) -> Result<()> {
        if let Some(client) = self.display_client()? {
            self.cli(&[
                "--client",
                client,
                "do",
                "session.select",
                "--args",
                &json!({"session_id": session, "window_id": window}).to_string(),
            ])?;
        }
        Ok(())
    }

    fn focus_window(&self, target: (String, String)) -> Result<()> {
        self.display_client()?;
        self.window_change("session.focus_window", target.clone())?;
        self.display_window(&target.0, &target.1)
    }

    fn api<T: DeserializeOwned>(&self, method: &str, args: Value) -> Result<T> {
        parse(&self.cli(&["api", "call", method, &args.to_string()])?)
            .with_context(|| format!("Invalid Rex {method} response"))
    }

    fn change(&self, method: &str, args: Value) -> Result<()> {
        let _: Value = self.api(method, args)?;
        Ok(())
    }

    fn sessions(&self) -> Result<Vec<Session>> {
        let list: SessionList = self.api("session.list", json!({}))?;
        Ok(list.sessions.unwrap_or_default())
    }

    fn view(&self, session_id: &str) -> Result<View> {
        self.api("session.view", json!({"session_id": session_id}))
    }

    fn views(&self) -> Result<Vec<View>> {
        let mut views = Vec::new();
        for session in self.sessions()? {
            if let Some(view) =
                self.observe(&session.session_id, None, || self.view(&session.session_id))?
            {
                views.push(view);
            }
        }
        Ok(views)
    }

    fn observe<T>(
        &self,
        session: &str,
        block: Option<&str>,
        query: impl FnOnce() -> Result<T>,
    ) -> Result<Option<T>> {
        match query() {
            Ok(value) => Ok(Some(value)),
            Err(error) => {
                if error
                    .downcast_ref::<CliFailure>()
                    .is_some_and(CliFailure::resource_missing)
                {
                    if !self.sessions()?.iter().any(|s| s.session_id == session) {
                        return Ok(None);
                    }
                    if let Some(block) = block
                        && !self
                            .observed_blocks(session)?
                            .iter()
                            .any(|b| b.block_id == block)
                    {
                        return Ok(None);
                    }
                }
                Err(error)
            }
        }
    }

    fn observed_blocks(&self, session: &str) -> Result<Vec<Block>> {
        Ok(self
            .observe(session, None, || self.blocks(session))?
            .unwrap_or_default())
    }

    fn current_view(&self) -> Result<View> {
        let sessions = self.sessions()?;
        if let Ok(id) = std::env::var("REX_SESSION") {
            let session = unique(
                sessions.into_iter().filter(|s| s.session_id == id),
                "session",
            )?;
            return self.view(&session.session_id);
        }
        let session = unique(sessions.into_iter(), "session (set REX_SESSION)")?;
        self.view(&session.session_id)
    }

    fn blocks(&self, session_id: &str) -> Result<Vec<Block>> {
        let list: BlockList = self.api("session.list_blocks", json!({"session_id": session_id}))?;
        Ok(list.blocks.unwrap_or_default())
    }

    fn pane_session(&self, pane_id: &str) -> Result<String> {
        for session in self.sessions()? {
            if self
                .blocks(&session.session_id)?
                .iter()
                .any(|b| b.block_id == pane_id)
            {
                return Ok(session.session_id);
            }
        }
        bail!("Rex block {pane_id:?} not found")
    }

    fn target_views(&self, target: &WindowTarget) -> Result<Vec<View>> {
        if target.parent_session.is_none() && target.window_id.is_none() {
            Ok(vec![self.current_view()?])
        } else {
            self.views()
        }
    }

    fn window_target(&self, target: &WindowTarget) -> Result<(String, String)> {
        unique(
            matching_windows(self.target_views(target)?, target).into_iter(),
            "window",
        )
    }

    fn at_pane(&self, pane_id: &str) -> Result<(String, String)> {
        let session_id = self.pane_session(pane_id)?;
        let block = unique(
            self.blocks(&session_id)?
                .into_iter()
                .filter(|b| b.block_id == pane_id),
            "block",
        )?;
        Ok((
            session_id,
            block
                .window_id
                .ok_or_else(|| anyhow!("Rex block is detached"))?,
        ))
    }

    fn named_window(&self, name: &str) -> Result<(String, String)> {
        self.window_target(&WindowTarget::new(name.to_owned(), None))
    }

    fn remember(&self, id: &str) -> Result<()> {
        self.created_blocks
            .lock()
            .map_err(|_| anyhow!("Rex block lock poisoned"))?
            .insert(id.to_owned());
        Ok(())
    }

    fn block_method<T: DeserializeOwned>(
        &self,
        session: &str,
        block: &str,
        method: &str,
        args: Value,
    ) -> Result<T> {
        self.api(
            &format!("{TERMINAL}.{method}"),
            json!({
                "session_id": session, "block_id": block, "args": args
            }),
        )
    }

    fn window_change(&self, method: &str, target: (String, String)) -> Result<()> {
        self.change(
            method,
            json!({"session_id": target.0, "window_id": target.1}),
        )
    }

    fn window_script(&self, method: &str, target: (String, String)) -> Result<String> {
        Ok(api_script(
            self.endpoint()?,
            method,
            json!({
                "session_id": target.0, "window_id": target.1
            }),
        ))
    }

    fn unsupported_sessions<T>(&self) -> Result<T> {
        bail!("Session operations are not supported by the Rex backend; use window mode")
    }

    fn live_info(&self, view: &View, block: &Block) -> Result<Option<LivePaneInfo>> {
        self.observe(&view.session_id, Some(&block.block_id), || {
            let processes: Processes =
                self.block_method(&view.session_id, &block.block_id, "process", json!({}))?;
            // Missing process details alone do not prove that the program exited.
            if processes.last_exit.is_some() {
                return Ok(None);
            }
            let title: Title =
                self.block_method(&view.session_id, &block.block_id, "title", json!({}))?;
            let window = view
                .windows
                .as_deref()
                .unwrap_or_default()
                .iter()
                .find(|w| Some(&w.window_id) == block.window_id.as_ref());
            let mut info = map_live_info(view, block, processes, title);
            info.window = window.map(|w| w.label.clone());
            Ok(Some(info))
        })
        .map(Option::flatten)
    }
}

fn matching_windows(views: Vec<View>, target: &WindowTarget) -> Vec<(String, String)> {
    let mut matches = Vec::new();
    for view in views {
        if target
            .parent_session
            .as_ref()
            .is_some_and(|parent| *parent != view.session_id && *parent != view.label)
        {
            continue;
        }
        for window in view.windows.unwrap_or_default() {
            // Stable IDs remain authoritative after a rename or name reuse.
            if target.window_id.as_ref().map_or_else(
                || window.label == target.full_name,
                |id| window.window_id == *id,
            ) {
                matches.push((view.session_id.clone(), window.window_id));
            }
        }
    }
    matches
}

fn choose_app(clients: Vec<Client>) -> Result<Option<String>> {
    let mut apps = clients
        .into_iter()
        .filter(|client| client.info.as_ref().is_some_and(|info| info.kind == "app"));
    let first = apps.next().map(|client| client.client_id);
    if apps.next().is_some() {
        bail!("Several Rex apps are connected; set REX_CLIENT to the app to switch");
    }
    Ok(first)
}

fn display_script(endpoint: &str, client: &str, session: &str, window: &str) -> String {
    format!(
        "env -u REX_SESSION -u REX_BLOCK -u REX_WINDOW -u REX_CLIENT rex --autostart=false --server {} --client {} do session.select --args {} >/dev/null",
        shell_quote(endpoint),
        shell_quote(client),
        shell_quote(&json!({"session_id": session, "window_id": window}).to_string()),
    )
}

fn terminal_layout(cwd: &Path, command: Option<&str>) -> Result<Value> {
    let mut options = json!({"cwd": cwd.to_str().context("Non-UTF-8 Rex cwd")?});
    if let Some(command) = command {
        options["shell"] = json!("none");
        options["command"] = json!(["sh", "-c", command]);
    }
    Ok(json!({"block": {"flavor": "com.superlogical.terminal.shell", "options": options}}))
}

fn nullable<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

fn parse<T: DeserializeOwned>(output: &str) -> Result<T> {
    serde_json::from_str(output).context("Failed to parse Rex JSON")
}

fn unique<T>(mut matches: impl Iterator<Item = T>, resource: &str) -> Result<T> {
    let first = matches
        .next()
        .ok_or_else(|| anyhow!("Rex {resource} not found"))?;
    if matches.next().is_some() {
        bail!("Ambiguous Rex {resource}; use a stable ID or session qualifier");
    }
    Ok(first)
}

fn api_script(endpoint: &str, method: &str, args: Value) -> String {
    format!(
        "env -u REX_SESSION -u REX_BLOCK -u REX_WINDOW -u REX_CLIENT rex --autostart=false --server {} api call {} {} >/dev/null",
        shell_quote(endpoint),
        shell_quote(method),
        shell_quote(&args.to_string())
    )
}

fn map_live_info(view: &View, block: &Block, processes: Processes, title: Title) -> LivePaneInfo {
    let foreground = processes.foreground.as_ref();
    let child = processes.child.as_ref();
    LivePaneInfo {
        pid: child.map(|p| p.pid),
        current_command: foreground.map(|p| p.name.clone()),
        working_dir: foreground
            .and_then(|p| p.cwd.clone())
            .or_else(|| child.and_then(|p| p.cwd.clone()))
            .unwrap_or_default(),
        title: (!title.title.is_empty()).then_some(title.title),
        session: Some(view.label.clone()),
        window: None,
        session_id: Some(view.session_id.clone()),
        window_id: block.window_id.clone(),
        window_index: None,
    }
}

/// Unknown named keys fail rather than typing their names into a shell.
fn key_payload(key: &str) -> Result<Value> {
    let mut key = key;
    let mut shift = false;
    let mut ctrl = false;
    let mut alt = false;
    loop {
        if let Some(rest) = key.strip_prefix("C-").or_else(|| key.strip_prefix("ctrl+")) {
            ctrl = true;
            key = rest;
        } else if let Some(rest) = key.strip_prefix("M-").or_else(|| key.strip_prefix("alt+")) {
            alt = true;
            key = rest;
        } else if let Some(rest) = key
            .strip_prefix("S-")
            .or_else(|| key.strip_prefix("shift+"))
        {
            shift = true;
            key = rest;
        } else {
            break;
        }
    }
    let lower = key.to_ascii_lowercase();
    let (physical, text, codepoint) = match lower.as_str() {
        "enter" | "return" => ("enter".to_owned(), "\r".to_owned(), 13),
        "escape" | "esc" => ("escape".to_owned(), String::new(), 27),
        "tab" => ("tab".to_owned(), "\t".to_owned(), 9),
        "space" => ("space".to_owned(), " ".to_owned(), 32),
        "bspace" | "backspace" => ("backspace".to_owned(), String::new(), 127),
        "up" | "down" | "left" | "right" => (format!("arrow_{lower}"), String::new(), 0),
        "home" | "end" | "insert" | "delete" => (lower.clone(), String::new(), 0),
        "pageup" | "ppage" => ("page_up".to_owned(), String::new(), 0),
        "pagedown" | "npage" => ("page_down".to_owned(), String::new(), 0),
        _ if lower
            .strip_prefix('f')
            .and_then(|s| s.parse::<u8>().ok())
            .is_some_and(|n| (1..=25).contains(&n)) =>
        {
            (lower.clone(), String::new(), 0)
        }
        _ if key.chars().count() == 1 => {
            let ch = key.chars().next().unwrap();
            shift |= ch.is_ascii_uppercase();
            let base = ch.to_ascii_lowercase();
            let physical = if base.is_ascii_alphabetic() {
                format!("key_{base}")
            } else if base.is_ascii_digit() {
                format!("digit_{base}")
            } else {
                match base {
                    ' ' => "space",
                    '-' => "minus",
                    '=' => "equal",
                    '[' => "bracket_left",
                    ']' => "bracket_right",
                    '\\' => "backslash",
                    ';' => "semicolon",
                    '\'' => "quote",
                    ',' => "comma",
                    '.' => "period",
                    '/' => "slash",
                    '`' => "backquote",
                    _ => "unidentified",
                }
                .to_owned()
            };
            let text = if ctrl || alt {
                String::new()
            } else if shift {
                ch.to_uppercase().collect()
            } else {
                ch.to_string()
            };
            (physical, text, base as i32)
        }
        _ => bail!("Unsupported Rex key: {key:?}"),
    };
    let mods = [(shift, "shift"), (ctrl, "ctrl"), (alt, "alt")]
        .into_iter()
        .filter_map(|(enabled, name)| enabled.then_some(name))
        .collect::<Vec<_>>()
        .join("+");
    Ok(
        json!({"key": physical, "mods": mods, "consumed_mods": if shift { "shift" } else { "" },
        "text": text, "unshifted_codepoint": codepoint, "composing": false, "action": "press"}),
    )
}

impl Multiplexer for RexBackend {
    fn name(&self) -> &'static str {
        "rex"
    }

    fn is_running(&self) -> Result<bool> {
        // Connection failures are not evidence of an empty set of agents.
        let _: Identity = parse(&self.cli(&["whoami", "--json"])?)?;
        Ok(true)
    }

    fn current_pane_id(&self) -> Option<String> {
        std::env::var("REX_BLOCK").ok()
    }

    fn active_pane_id(&self) -> Option<String> {
        let view = self.current_view().ok()?;
        view.windows?
            .into_iter()
            .find(|w| Some(&w.window_id) == view.active_window_id.as_ref())?
            .focused_block_id
    }

    fn current_session_id(&self) -> Result<Option<String>> {
        Ok(Some(self.current_view()?.session_id))
    }
    fn current_window_id(&self) -> Result<Option<String>> {
        if let Some(pane) = self.current_pane_id() {
            return Ok(Some(self.at_pane(&pane)?.1));
        }
        Ok(self.current_view()?.active_window_id)
    }
    fn rightmost_window_id(&self) -> Result<Option<String>> {
        Ok(self
            .current_view()?
            .windows
            .unwrap_or_default()
            .last()
            .map(|w| w.window_id.clone()))
    }
    fn current_session(&self) -> Option<String> {
        self.current_view().ok().map(|v| v.label)
    }

    fn get_client_active_pane_path(&self) -> Result<PathBuf> {
        let pane = self
            .active_pane_id()
            .ok_or_else(|| anyhow!("No active Rex block"))?;
        self.get_live_pane_info(&pane)?
            .map(|p| p.working_dir)
            .ok_or_else(|| anyhow!("Active Rex block disappeared"))
    }

    fn create_window(&self, params: CreateWindowParams) -> Result<String> {
        let view = self.current_view()?;
        let before = if let Some(after) = params.after_window {
            let windows = view.windows.as_deref().unwrap_or_default();
            let index = windows
                .iter()
                .position(|w| w.window_id == after)
                .ok_or_else(|| {
                    anyhow!("Rex placement window {after:?} not found in current session")
                })?;
            windows.get(index + 1).map(|w| w.window_id.clone())
        } else {
            None
        };
        let name = util::prefixed(params.prefix, params.name);
        let created: Created = self.api(
            "session.new_window",
            json!({
                "session_id": view.session_id, "window_label": name, "focus": false,
                "layout": terminal_layout(params.cwd, None)?
            }),
        )?;
        let pane = created.pane_id()?;
        self.remember(&pane)?;
        if params.after_window.is_some() {
            let window = created
                .window_id
                .context("Rex did not return a window ID")?;
            if let Err(error) = self.change(
                "session.move_window",
                json!({"session_id": view.session_id,
                "window_id": window, "before_window_id": before}),
            ) {
                self.window_change("session.close_window", (view.session_id, window))
                    .with_context(|| {
                        format!("Rex window placement failed: {error:#}; cleanup also failed")
                    })?;
                return Err(error.context("Failed to place new Rex window"));
            }
        }
        Ok(pane)
    }

    fn create_session(&self, _: CreateSessionParams) -> Result<String> {
        self.unsupported_sessions()
    }
    fn switch_to_session(&self, _: &str, _: &str) -> Result<()> {
        self.unsupported_sessions()
    }
    fn kill_session(&self, _: &str) -> Result<()> {
        self.unsupported_sessions()
    }
    fn schedule_session_close(&self, _: &str, _: Duration) -> Result<()> {
        self.unsupported_sessions()
    }
    fn wait_until_session_closed(&self, _: &str) -> Result<()> {
        self.unsupported_sessions()
    }
    fn shell_switch_session_cmd(&self, _: &str) -> Result<String> {
        self.unsupported_sessions()
    }
    fn shell_kill_session_cmd(&self, _: &str) -> Result<String> {
        self.unsupported_sessions()
    }

    fn session_exists(&self, name: &str) -> Result<bool> {
        Ok(self
            .sessions()?
            .iter()
            .any(|s| s.label == name || s.session_id == name))
    }
    fn get_all_session_names(&self) -> Result<HashSet<String>> {
        Ok(self.sessions()?.into_iter().map(|s| s.label).collect())
    }
    fn get_window_names_in_session(&self, name: &str) -> Result<HashSet<String>> {
        let session = unique(
            self.sessions()?
                .into_iter()
                .filter(|s| s.label == name || s.session_id == name),
            "session",
        )?;
        Ok(self
            .view(&session.session_id)?
            .windows
            .unwrap_or_default()
            .into_iter()
            .map(|w| w.label)
            .collect())
    }
    fn get_all_window_names(&self) -> Result<HashSet<String>> {
        Ok(self
            .current_view()?
            .windows
            .unwrap_or_default()
            .into_iter()
            .map(|w| w.label)
            .collect())
    }
    fn get_all_windows_with_sessions(&self) -> Result<HashSet<(String, String)>> {
        Ok(self
            .views()?
            .into_iter()
            .flat_map(|v| {
                v.windows
                    .unwrap_or_default()
                    .into_iter()
                    .map(move |w| (w.label, v.label.clone()))
            })
            .collect())
    }
    fn get_all_window_names_all_sessions(&self) -> Result<HashSet<String>> {
        Ok(self
            .get_all_windows_with_sessions()?
            .into_iter()
            .map(|(w, _)| w)
            .collect())
    }
    fn current_window_name(&self) -> Result<Option<String>> {
        let view = self.current_view()?;
        let id = self.current_window_id()?;
        Ok(view
            .windows
            .unwrap_or_default()
            .into_iter()
            .find(|w| Some(&w.window_id) == id.as_ref())
            .map(|w| w.label))
    }

    fn select_window(&self, prefix: &str, name: &str) -> Result<()> {
        self.focus_window(self.named_window(&util::prefixed(prefix, name))?)
    }
    fn select_window_target(&self, target: &WindowTarget) -> Result<()> {
        self.focus_window(self.window_target(target)?)
    }
    fn kill_window(&self, full_name: &str) -> Result<()> {
        self.window_change("session.close_window", self.named_window(full_name)?)
    }
    fn kill_window_target(&self, target: &WindowTarget) -> Result<()> {
        self.window_change("session.close_window", self.window_target(target)?)
    }
    fn window_target_exists(&self, target: &WindowTarget) -> Result<bool> {
        Ok(!matching_windows(self.target_views(target)?, target).is_empty())
    }
    fn rename_window(&self, old: &str, new: &str) -> Result<()> {
        let (session, window) = self.named_window(old)?;
        self.change(
            "session.set_window_label",
            json!({"session_id": session, "window_id": window, "label": new}),
        )
    }
    fn rename_window_at_pane(&self, pane: &str, new: &str) -> Result<()> {
        let (session, window) = self.at_pane(pane)?;
        self.change(
            "session.set_window_label",
            json!({"session_id": session, "window_id": window, "label": new}),
        )
    }
    fn shell_select_window_cmd(&self, name: &str) -> Result<String> {
        let target = self.named_window(name)?;
        let mut script = self.window_script("session.focus_window", target.clone())?;
        if let Some(client) = self.display_client()? {
            script.push_str(" && ");
            script.push_str(&display_script(
                self.endpoint()?,
                client,
                &target.0,
                &target.1,
            ));
        }
        Ok(script)
    }
    fn shell_kill_window_cmd(&self, name: &str) -> Result<String> {
        self.window_script("session.close_window", self.named_window(name)?)
    }
    fn shell_kill_window_target_cmd(&self, target: &WindowTarget) -> Result<String> {
        self.window_script("session.close_window", self.window_target(target)?)
    }
    fn shell_close_window_by_id_guard_cmd(&self, id: &str) -> Result<String> {
        let target =
            self.window_target(&WindowTarget::with_id(String::new(), None, id.to_owned()))?;
        self.window_script("session.close_window", target)
    }
    fn schedule_window_close(&self, name: &str, delay: Duration) -> Result<()> {
        self.run_deferred_script(&format!(
            "sleep {}; {}",
            shell_quote(&delay.as_secs_f64().to_string()),
            self.shell_kill_window_cmd(name)?
        ))
    }
    fn schedule_window_target_close(&self, target: &WindowTarget, delay: Duration) -> Result<()> {
        self.run_deferred_script(&format!(
            "sleep {}; {}",
            shell_quote(&delay.as_secs_f64().to_string()),
            self.shell_kill_window_target_cmd(target)?
        ))
    }
    fn run_deferred_script(&self, script: &str) -> Result<()> {
        util::run_detached_sh_c(script)
    }

    fn select_pane(&self, pane_id: &str) -> Result<()> {
        let (session, window) = self.at_pane(pane_id)?;
        self.display_client()?;
        self.change(
            "session.focus_block",
            json!({"session_id": session, "block_id": pane_id}),
        )?;
        self.display_window(&session, &window)
    }
    fn switch_to_pane(&self, pane_id: &str, _: Option<&str>) -> Result<()> {
        self.select_pane(pane_id)
    }
    fn zoom_pane(&self, pane_id: &str) -> Result<()> {
        self.change(
            "session.zoom_block",
            json!({"session_id": self.pane_session(pane_id)?, "block_id": pane_id, "zoom": true}),
        )
    }
    fn kill_pane(&self, pane_id: &str) -> Result<()> {
        self.change(
            "block.close",
            json!({"session_id": self.pane_session(pane_id)?, "block_id": pane_id}),
        )
    }
    fn set_pane_name(&self, pane_id: &str, name: &str) -> Result<()> {
        self.change(
            "session.set_block_label",
            json!({"session_id": self.pane_session(pane_id)?, "block_id": pane_id, "label": name}),
        )
    }
    fn respawn_pane(&self, pane_id: &str, cwd: &Path, cmd: Option<&str>) -> Result<String> {
        if !self
            .created_blocks
            .lock()
            .map_err(|_| anyhow!("Rex block lock poisoned"))?
            .contains(pane_id)
        {
            bail!("Rex can only respawn a fresh block created by this backend");
        }
        let new_id = self.split_pane(pane_id, &SplitDirection::Vertical, cwd, None, None, cmd)?;
        if let Err(error) = self.kill_pane(pane_id) {
            self.kill_pane(&new_id).with_context(|| {
                format!("Rex respawn failed: {error:#}; replacement cleanup also failed")
            })?;
            return Err(error.context("Failed to close original Rex block during respawn"));
        }
        self.created_blocks
            .lock()
            .map_err(|_| anyhow!("Rex block lock poisoned"))?
            .remove(pane_id);
        Ok(new_id)
    }
    fn split_pane(
        &self,
        target: &str,
        direction: &SplitDirection,
        cwd: &Path,
        size: Option<u16>,
        percentage: Option<u8>,
        command: Option<&str>,
    ) -> Result<String> {
        if size.is_some() {
            bail!("Absolute split sizes are not supported by the Rex backend; use percentage");
        }
        let direction = match direction {
            SplitDirection::Horizontal => "right",
            SplitDirection::Vertical => "below",
            SplitDirection::Stacked => bail!("Stacked panes are not supported by the Rex backend"),
        };
        let percentage = percentage.unwrap_or(50);
        if !(1..=99).contains(&percentage) {
            bail!("Rex split percentage must be between 1 and 99");
        }
        let session = self.pane_session(target)?;
        let ratio = percentage.to_string();
        let mut args = vec![
            "split",
            "-s",
            &session,
            "-b",
            target,
            "--split",
            direction,
            "--ratio",
            &ratio,
            "--focus=false",
            "--json",
            "-c",
            cwd.to_str().context("Non-UTF-8 Rex cwd")?,
        ];
        if let Some(command) = command {
            args.extend(["--shell=none", "--", "sh", "-c", command]);
        }
        let created: Created = parse(&self.cli(&args)?)?;
        let id = created.pane_id()?;
        self.remember(&id)?;
        Ok(id)
    }
    fn capture_pane(&self, pane_id: &str, lines: u16) -> Option<String> {
        let session = self.pane_session(pane_id).ok()?;
        let output = self
            .cli(&["capture", "-s", &session, "-b", pane_id, "--trim"])
            .ok()?;
        Some(util::tail_lines(&output, lines))
    }
    fn send_text_fragment(&self, pane_id: &str, text: &str) -> Result<()> {
        let _: Value = self.block_method(
            &self.pane_session(pane_id)?,
            pane_id,
            "write",
            json!({"data": text}),
        )?;
        Ok(())
    }
    fn send_enter(&self, pane_id: &str) -> Result<()> {
        self.send_key(pane_id, "Enter")
    }
    fn send_key(&self, pane_id: &str, key: &str) -> Result<()> {
        // Unlike `rex send-key`, direct block events bypass Rex keybindings.
        // Dashboard input must reach the program even when Rex binds that key.
        let payload = key_payload(key)?;
        let session = self.pane_session(pane_id)?;
        self.change(
            "block.event",
            json!({"session_id": session, "block_id": pane_id,
            "event": {"type": "key", "payload": payload}}),
        )?;
        let mut release = payload;
        release["action"] = json!("release");
        self.change(
            "block.event",
            json!({"session_id": session, "block_id": pane_id,
            "event": {"type": "key", "payload": release}}),
        )
    }
    fn paste_text(&self, pane_id: &str, content: &str) -> Result<()> {
        self.change(
            "block.event",
            json!({"session_id": self.pane_session(pane_id)?, "block_id": pane_id,
            "event": {"type": "paste", "payload": {"text": content}}}),
        )
    }
    fn clear_pane(&self, pane_id: &str) -> Result<()> {
        let _: Value =
            self.block_method(&self.pane_session(pane_id)?, pane_id, "clear", json!({}))?;
        Ok(())
    }
    // Rex supports OSC 7501 status from terminal OUTPUT, but `write` sends INPUT.
    // This icon-only API cannot safely report semantic status to a target pane.
    // Workmux agent state remains in StateStore.
    fn set_status(&self, _: &str, _: &str, _: bool) -> Result<()> {
        Ok(())
    }
    fn clear_status(&self, _: &str) -> Result<()> {
        Ok(())
    }
    fn ensure_status_format(&self, _: &str) -> Result<()> {
        Ok(())
    }

    fn instance_id(&self) -> String {
        self.resolve_instance_id()
            .unwrap_or_else(|_| self.server.clone().unwrap_or_default())
    }
    fn resolve_instance_id(&self) -> Result<String> {
        Ok(self.endpoint()?.to_owned())
    }
    fn server_boot_id(&self) -> Result<Option<String>> {
        let identity: Identity = parse(&self.cli(&["whoami", "--json"])?)?;
        Ok(Some(identity.instance_id))
    }
    fn get_live_pane_info(&self, pane_id: &str) -> Result<Option<LivePaneInfo>> {
        for view in self.views()? {
            if let Some(block) = self
                .observed_blocks(&view.session_id)?
                .into_iter()
                .find(|b| b.block_id == pane_id && b.creator_name == TERMINAL)
            {
                let info = self.live_info(&view, &block)?;
                // Individual snapshots feed status persistence, which must not
                // replace a healthy process identity with missing-value defaults.
                if let Some(info) = &info
                    && (info.pid.is_none()
                        || info.current_command.as_deref().is_none_or(str::is_empty)
                        || info.working_dir.as_os_str().is_empty())
                {
                    bail!("Rex process details unavailable for block {pane_id:?}");
                }
                return Ok(info);
            }
        }
        Ok(None)
    }
    fn get_all_live_pane_info(&self) -> Result<HashMap<String, LivePaneInfo>> {
        let mut panes = HashMap::new();
        for view in self.views()? {
            for block in self.observed_blocks(&view.session_id)? {
                if block.creator_name == TERMINAL
                    && let Some(info) = self.live_info(&view, &block)?
                {
                    panes.insert(block.block_id.clone(), info);
                }
            }
        }
        Ok(panes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_selection_ignores_cli_connections_and_rejects_ambiguity() {
        let list: ClientList = parse(
            r#"{"clients":[
            {"client_id":"cli","info":{"kind":"cli"}},
            {"client_id":"unknown"},
            {"client_id":"app","info":{"kind":"app"}}
        ]}"#,
        )
        .unwrap();
        assert_eq!(
            choose_app(list.clients.unwrap()).unwrap().as_deref(),
            Some("app")
        );
        assert!(choose_app(vec![]).unwrap().is_none());
        let list: ClientList = parse(
            r#"{"clients":[
            {"client_id":"one","info":{"kind":"app"}},
            {"client_id":"two","info":{"kind":"app"}}
        ]}"#,
        )
        .unwrap();
        assert!(choose_app(list.clients.unwrap()).is_err());
    }

    #[test]
    fn deferred_display_quotes_ids_and_selects_the_window() {
        let script = display_script("unix:///tmp/a b", "app 'one'", "session:1", "window:2");
        let words = shlex::split(&script).unwrap();
        let client = words.iter().position(|word| word == "--client").unwrap();
        assert_eq!(words[client + 1], "app 'one'");
        let args = words.iter().position(|word| word == "--args").unwrap();
        let selection: Value = serde_json::from_str(&words[args + 1]).unwrap();
        assert_eq!(
            selection,
            json!({"session_id":"session:1", "window_id":"window:2"})
        );
    }

    #[test]
    fn constructors_defer_server_resolution() {
        let backend = RexBackend::new();
        assert!(backend.server.is_none());
        assert!(backend.endpoint.get().is_none());
        let backend = RexBackend::for_server("unix:///tmp/explicit.sock");
        assert_eq!(backend.server.as_deref(), Some("unix:///tmp/explicit.sock"));
        assert!(backend.endpoint.get().is_none());
    }

    #[test]
    fn snapshots_accept_null_lists_but_reject_missing_or_malformed_data() {
        assert!(
            parse::<SessionList>(r#"{"sessions":null}"#)
                .unwrap()
                .sessions
                .is_none()
        );
        assert!(
            parse::<BlockList>(r#"{"blocks":null}"#)
                .unwrap()
                .blocks
                .is_none()
        );
        for invalid in [
            "{}",
            r#"{"sessions":{}}"#,
            r#"{"sessions":[{"label":"x"}]}"#,
            "not json",
        ] {
            assert!(parse::<SessionList>(invalid).is_err(), "{invalid}");
        }
        assert!(parse::<BlockList>("{}").is_err());
        assert!(parse::<Processes>("{}").is_err());
        assert!(parse::<Processes>(r#"{"last_exit":{}}"#).is_err());
        assert!(
            parse::<Processes>(r#"{"last_exit":null,"child":{"pid":"bad","name":"sh"}}"#).is_err()
        );
        assert!(
            parse::<View>(
                r#"{"session_id":"s","label":"work","windows":[{"label":"missing id"}]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn live_pane_mapping_keeps_stable_ids_and_child_pid() {
        let view: View =
            parse(r#"{"session_id":"session:one","label":"work","windows":null}"#).unwrap();
        let block: Block = parse(r#"{"block_id":"block:one","creator_name":"com.superlogical.terminal","window_id":"window:one"}"#).unwrap();
        let processes: Processes = parse(r#"{"last_exit":null,"child":{"pid":12,"name":"sh","cwd":"/tmp"},"foreground":{"pid":34,"name":"agent","cwd":"/work"}}"#).unwrap();
        let info = map_live_info(
            &view,
            &block,
            processes,
            Title {
                title: "task".into(),
            },
        );
        assert_eq!(info.pid, Some(12));
        assert_eq!(info.current_command.as_deref(), Some("agent"));
        assert_eq!(info.working_dir, Path::new("/work"));
        assert_eq!(info.session.as_deref(), Some("work"));
        assert_eq!(info.session_id.as_deref(), Some("session:one"));
        assert_eq!(info.window_id.as_deref(), Some("window:one"));
        assert_eq!(info.title.as_deref(), Some("task"));
    }

    #[test]
    fn unavailable_process_mapping_does_not_invent_a_pid() {
        let view: View = parse(r#"{"session_id":"s","label":"work"}"#).unwrap();
        let block: Block =
            parse(r#"{"block_id":"b","creator_name":"com.superlogical.terminal"}"#).unwrap();
        let processes: Processes = parse(r#"{"last_exit":null}"#).unwrap();
        let info = map_live_info(
            &view,
            &block,
            processes,
            Title {
                title: String::new(),
            },
        );
        assert!(info.pid.is_none());
        assert!(info.current_command.is_none());
        assert!(info.window_id.is_none());
        assert!(info.title.is_none());
    }

    #[test]
    fn creation_requires_one_nonempty_block_id() {
        for ids in [json!([]), json!([""]), json!(["a", "b"]), json!([null])] {
            let result = serde_json::from_value::<Created>(json!({"block_ids": ids}));
            assert!(result.is_err() || result.unwrap().pane_id().is_err());
        }
        let created: Created =
            parse(r#"{"block_ids":["block:one"],"window_id":"window:one"}"#).unwrap();
        assert_eq!(created.pane_id().unwrap(), "block:one");
    }

    #[test]
    fn unsupported_operations_fail_before_contacting_a_server() {
        let backend = RexBackend::for_server("unix:///nonexistent/rex.sock");
        assert!(backend.kill_session("anything").is_err());
        assert!(backend.switch_to_session("", "anything").is_err());
        assert!(
            backend
                .split_pane(
                    "b",
                    &SplitDirection::Stacked,
                    Path::new("/tmp"),
                    None,
                    None,
                    None
                )
                .is_err()
        );
        assert!(
            backend
                .split_pane(
                    "b",
                    &SplitDirection::Horizontal,
                    Path::new("/tmp"),
                    Some(10),
                    None,
                    None
                )
                .is_err()
        );
        assert!(
            backend
                .split_pane(
                    "b",
                    &SplitDirection::Horizontal,
                    Path::new("/tmp"),
                    None,
                    Some(100),
                    None
                )
                .is_err()
        );
        assert!(backend.endpoint.get().is_none());
    }

    #[test]
    fn ambiguous_names_fail_instead_of_selecting_the_first() {
        assert!(unique([1, 2].into_iter(), "window").is_err());
        assert!(unique(Vec::<i32>::new().into_iter(), "window").is_err());
        assert_eq!(unique([1].into_iter(), "window").unwrap(), 1);
    }

    #[test]
    fn window_targets_use_stable_ids_and_session_qualifiers() {
        let views = || {
            vec![
            parse::<View>(r#"{"session_id":"s1","label":"one","windows":[{"window_id":"w1","label":"renamed"},{"window_id":"w2","label":"old"}]}"#).unwrap(),
            parse::<View>(r#"{"session_id":"s2","label":"two","windows":[{"window_id":"w3","label":"old"}]}"#).unwrap(),
        ]
        };
        let stable = WindowTarget::with_id("old".into(), None, "w1".into());
        assert_eq!(
            matching_windows(views(), &stable),
            [("s1".into(), "w1".into())]
        );
        let qualified = WindowTarget::new("old".into(), Some("two".into()));
        assert_eq!(
            matching_windows(views(), &qualified),
            [("s2".into(), "w3".into())]
        );
        let wrong_parent = WindowTarget::with_id("old".into(), Some("s2".into()), "w1".into());
        assert!(matching_windows(views(), &wrong_parent).is_empty());
        let missing_id = WindowTarget::with_id("old".into(), None, "gone".into());
        assert!(matching_windows(views(), &missing_id).is_empty());
        let ambiguous = WindowTarget::new("old".into(), None);
        assert!(unique(matching_windows(views(), &ambiguous).into_iter(), "window").is_err());
    }

    #[test]
    fn command_targeting_removes_inherited_context_and_disables_autostart() {
        let command = RexBackend::command_for(Some("unix:///tmp/rex socket"));
        let args: Vec<_> = command.get_args().map(|s| s.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "--autostart=false",
                "--color=never",
                "--server",
                "unix:///tmp/rex socket"
            ]
        );
        for name in ["REX_SESSION", "REX_BLOCK", "REX_WINDOW", "REX_CLIENT"] {
            assert!(
                command
                    .get_envs()
                    .any(|(key, value)| key == name && value.is_none())
            );
        }
    }

    #[test]
    fn deferred_command_quotes_server_method_and_json_as_separate_arguments() {
        let endpoint = "unix:///tmp/a 'quoted' socket; touch /tmp/never";
        let args = json!({"session_id": "s'$(false)", "window_id": "w; false"});
        let script = api_script(endpoint, "session.close_window", args.clone());
        assert!(script.starts_with("env -u REX_SESSION -u REX_BLOCK -u REX_WINDOW -u REX_CLIENT rex --autostart=false --server "));
        assert!(script.contains(&shell_quote(endpoint)));
        assert!(script.ends_with(&format!("{} >/dev/null", shell_quote(&args.to_string()))));
        let output = Command::new("sh")
            .args([
                "-c",
                &format!(
                    "set -- {} {}; printf '%s\\n' \"$1\" \"$2\"",
                    shell_quote(endpoint),
                    shell_quote(&args.to_string())
                ),
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("{endpoint}\n{args}\n")
        );
    }

    #[test]
    fn terminal_layout_preserves_command_and_cwd_without_shell_interpolation() {
        let command = "echo \"a'b\"; exec sh";
        let layout = terminal_layout(Path::new("/tmp/a'b $dir"), Some(command)).unwrap();
        assert_eq!(
            layout["block"]["options"]["command"],
            json!(["sh", "-c", command])
        );
        assert_eq!(layout["block"]["options"]["shell"], "none");
        assert_eq!(layout["block"]["options"]["cwd"], "/tmp/a'b $dir");
        assert!(
            terminal_layout(Path::new("/tmp"), None).unwrap()["block"]["options"]
                .get("command")
                .is_none()
        );
    }

    #[test]
    fn key_conversion_preserves_case_modifiers_and_named_keys() {
        assert_eq!(key_payload("Enter").unwrap()["key"], "enter");
        assert_eq!(key_payload("Escape").unwrap()["key"], "escape");
        assert_eq!(key_payload("C-c").unwrap()["mods"], "ctrl");
        assert_eq!(key_payload("C-c").unwrap()["unshifted_codepoint"], 99);
        assert_eq!(key_payload("C-c").unwrap()["text"], "");
        assert_eq!(key_payload("M-S-Left").unwrap()["mods"], "shift+alt");
        assert_eq!(key_payload("M-S-Left").unwrap()["key"], "arrow_left");
        assert_eq!(key_payload("G").unwrap()["text"], "G");
        assert_eq!(key_payload("G").unwrap()["mods"], "shift");
        assert_eq!(key_payload("F12").unwrap()["key"], "f12");
        assert!(key_payload("NotAKey").is_err());
        assert!(key_payload("F26").is_err());
        for (alias, canonical) in [
            ("Return", "Enter"),
            ("Esc", "Escape"),
            ("BSpace", "Backspace"),
            ("PPage", "PageUp"),
            ("NPage", "PageDown"),
            ("ctrl+alt+shift+Left", "C-M-S-Left"),
        ] {
            assert_eq!(key_payload(alias).unwrap(), key_payload(canonical).unwrap());
        }
        for invalid in ["", "C-", "M-NotAKey", "F0", "F256"] {
            assert!(key_payload(invalid).is_err(), "{invalid:?}");
        }
    }

    /// Called by test_rex_key_events_bypass_bindings with a disposable server
    /// whose config consumes g and ctrl+x. Never point this at a user's server.
    #[test]
    #[ignore = "requires WORKMUX_REX_TEST_SERVER and disposable REX_SESSION"]
    fn live_key_events_on_isolated_server() -> Result<()> {
        let server = std::env::var("WORKMUX_REX_TEST_SERVER")?;
        let session = std::env::var("REX_SESSION")?;
        let backend = RexBackend::for_server(&server);
        let directory = tempfile::tempdir()?;
        let log = directory.path().join("keys");
        let reader = concat!(
            "import os,sys,tty\n",
            "tty.setraw(0)\n",
            "with open(sys.argv[1], 'wb', buffering=0) as f:\n",
            " f.write(b'READY')\n",
            " while True: f.write(os.read(0, 1024))\n",
        );
        let created: Created = parse(&backend.cli(&[
            "run",
            "-s",
            &session,
            "--focus=false",
            "--json",
            "--shell=none",
            "--",
            "python3",
            "-c",
            reader,
            log.to_str().unwrap(),
        ])?)?;
        let pane = created.pane_id()?;
        struct Cleanup<'a>(&'a RexBackend, String, String);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                let _ = self
                    .0
                    .window_change("session.close_window", (self.1.clone(), self.2.clone()));
            }
        }
        let _cleanup = Cleanup(&backend, session.clone(), created.window_id.unwrap());
        let wait_for = |expected: &[u8]| {
            for _ in 0..100 {
                if std::fs::read(&log).unwrap_or_default() == expected {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            assert_eq!(std::fs::read(&log).unwrap_or_default(), expected);
        };
        wait_for(b"READY");
        // Native CLI dispatch consumes these keys in Rex's bindings. The same
        // keys below must instead reach the raw PTY through the backend.
        backend.cli(&["send-key", "-s", &session, "-b", &pane, "g", "ctrl+x"])?;
        let mut expected = b"READY".to_vec();
        for (key, bytes) in [
            ("g", &b"g"[..]),
            ("G", b"G"),
            ("S-g", b"G"),
            ("C-x", b"\x18"),
            ("ctrl+c", b"\x03"),
            ("M-x", b"\x1bx"),
            ("Enter", b"\r"),
            ("Return", b"\r"),
            ("Escape", b"\x1b"),
            ("Esc", b"\x1b"),
            ("Tab", b"\t"),
            ("Space", b" "),
            ("BSpace", b"\x7f"),
            ("Left", b"\x1b[D"),
            ("S-Left", b"\x1b[1;2D"),
            ("M-S-Left", b"\x1b[1;4D"),
            ("Home", b"\x1b[H"),
            ("Delete", b"\x1b[3~"),
            ("PPage", b"\x1b[5~"),
            ("NPage", b"\x1b[6~"),
            ("F12", b"\x1b[24~"),
            ("!", b"!"),
            ("é", "é".as_bytes()),
        ] {
            backend.send_key(&pane, key)?;
            expected.extend_from_slice(bytes);
            wait_for(&expected);
        }
        for key in ["NotAKey", "F26", "C-", "M-NotAKey"] {
            assert!(backend.send_key(&pane, key).is_err(), "{key}");
        }
        wait_for(&expected);
        Ok(())
    }

    /// Opt in only against an isolated server with no app attached. The caller
    /// supplies a disposable session in REX_SESSION; cleanup closes only the
    /// tab and foreign-session fixture created by this test.
    #[test]
    #[ignore = "requires WORKMUX_REX_TEST_SERVER and disposable REX_SESSION"]
    fn live_primitives_on_isolated_server() -> Result<()> {
        let server = std::env::var("WORKMUX_REX_TEST_SERVER")?;
        let backend = RexBackend::for_server(&server);
        let original_window = backend.current_view()?.active_window_id;
        let cwd = std::env::current_dir()?;
        let pane = backend.create_window(CreateWindowParams {
            prefix: "workmux-test-",
            name: "primitives",
            cwd: &cwd,
            after_window: original_window.as_deref(),
        })?;
        let (session, window) = backend.at_pane(&pane)?;
        struct Cleanup<'a>(&'a RexBackend, String, String);
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                let _ = self
                    .0
                    .window_change("session.close_window", (self.1.clone(), self.2.clone()));
            }
        }
        let _cleanup = Cleanup(&backend, session.clone(), window.clone());
        assert_eq!(backend.current_view()?.active_window_id, original_window);
        assert!(
            backend
                .respawn_pane("not-created-here", &cwd, None)
                .is_err()
        );
        backend.rename_window_at_pane(&pane, "workmux-renamed")?;
        let target =
            WindowTarget::with_id("stale-name".into(), Some(session.clone()), window.clone());
        assert!(backend.window_target_exists(&target)?);
        let layout = [crate::config::PaneConfig {
            command: Some("printf 'WORKMUX_SETUP_READY\\n'".into()),
            ..Default::default()
        }];
        let setup = backend.setup_panes(
            &pane,
            &layout,
            &cwd,
            PaneSetupOptions {
                run_commands: true,
                prompt_file_path: None,
                worktree_root: None,
                lima_vm_name: None,
                resume_mode: ResumeMode::None,
                sandbox_supervisor: None,
                path_prefix: None,
            },
            &crate::config::Config::default(),
            None,
        )?;
        let replacement = setup.focus_pane_id;
        assert_ne!(replacement, pane);
        assert_eq!(backend.at_pane(&replacement)?.1, window);
        assert!(backend.get_live_pane_info(&pane)?.is_none());
        let split = backend.split_pane(
            &replacement,
            &SplitDirection::Horizontal,
            &cwd,
            None,
            Some(30),
            None,
        )?;
        assert_eq!(backend.at_pane(&split)?.1, window);
        assert_eq!(backend.current_view()?.active_window_id, original_window);
        backend.set_pane_name(&split, "test-pane")?;
        backend.select_window_target(&target)?;
        backend.select_pane(&replacement)?;
        backend.zoom_pane(&replacement)?;
        let focused: Value = backend.api("session.view", json!({"session_id": session}))?;
        let focused_window = focused["windows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|w| w["window_id"] == window)
            .unwrap();
        assert_eq!(focused_window["focused_block_id"], replacement);
        assert_eq!(focused_window["zoomed_block_id"], replacement);
        backend.send_keys(&replacement, "printf 'WORKMUX_REX_LIVE_OK\\n'")?;
        let mut captured = String::new();
        for _ in 0..40 {
            captured = backend.capture_pane(&replacement, 30).unwrap_or_default();
            if captured
                .lines()
                .any(|line| line.trim() == "WORKMUX_REX_LIVE_OK")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            captured
                .lines()
                .any(|line| line.trim() == "WORKMUX_REX_LIVE_OK"),
            "{captured}"
        );
        backend.paste_text(&replacement, "printf 'PASTE_OK\\n'")?;
        backend.send_enter(&replacement)?;
        backend.send_key(&replacement, "C-c")?;
        let live = backend.get_all_live_pane_info_strict()?;
        let info = &live[&replacement];
        assert!(info.pid.is_some());
        assert_eq!(info.window_id.as_deref(), Some(window.as_str()));
        assert_eq!(info.window.as_deref(), Some("workmux-renamed"));
        assert_eq!(info.session_id.as_deref(), Some(session.as_str()));
        assert!(backend.server_boot_id()?.is_some());
        assert!(backend.resolve_instance_id()?.starts_with("unix://"));
        let script = backend.shell_kill_window_target_cmd(&target)?;
        let status = Command::new("sh").args(["-c", &script]).status()?;
        assert!(status.success());
        assert!(!backend.window_target_exists(&target)?);

        // An inherited REX_SESSION must not redirect operations on foreign IDs.
        #[derive(Deserialize)]
        struct NewSession {
            session_id: String,
            initial_windows: Vec<Created>,
        }
        let label = format!(
            "workmux-test-foreign-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        );
        let foreign: NewSession = parse(&backend.cli(&["new", &label, "--json"])?)?;
        struct SessionCleanup<'a>(&'a RexBackend, String);
        impl Drop for SessionCleanup<'_> {
            fn drop(&mut self) {
                let _ = self
                    .0
                    .change("session.destroy", json!({"session_id": self.1}));
            }
        }
        let _foreign_cleanup = SessionCleanup(&backend, foreign.session_id.clone());
        let foreign_pane = foreign.initial_windows[0].pane_id()?;
        backend.switch_to_pane(&foreign_pane, None)?;
        let foreign_split = backend.split_pane(
            &foreign_pane,
            &SplitDirection::Vertical,
            &cwd,
            None,
            Some(40),
            None,
        )?;
        assert_eq!(backend.at_pane(&foreign_split)?.0, foreign.session_id);
        backend.rename_window_at_pane(&foreign_split, "foreign-renamed")?;
        assert_eq!(
            backend
                .get_live_pane_info(&foreign_split)?
                .unwrap()
                .session_id,
            Some(foreign.session_id)
        );
        assert_eq!(backend.current_view()?.session_id, session);
        println!(
            "live evidence: background tab + split retained active tab; respawn {pane} -> {replacement} retained {window}; handshake, input, capture, rename, focus, zoom, strict enumeration, deferred close passed"
        );
        Ok(())
    }
}
