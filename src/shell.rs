use crate::persona::PrebakedPersona;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

/// Result of executing a command line inside the zero-overhead in-memory Fake Shell.
#[derive(Debug, Clone)]
pub struct ShellExecResult {
    /// Text output to write back to the attacker's terminal (normalized with `\n`).
    pub output: String,
    /// Suggested artificial delay (in ms) before returning the output to waste attacker time.
    pub delay_ms: u64,
    /// Any malware download URLs, C2 endpoints, or dropped file contents captured.
    pub captured_indicators: Vec<String>,
    /// True if the attacker executed `exit` or `logout`.
    pub should_exit: bool,
}

/// Lightweight in-memory state machine simulating a full Ubuntu 22.04 LTS interactive bash shell.
/// Uses a bounded Copy-on-Write (CoW) overlay on top of the shared `PrebakedPersona` template
/// so each session costs <2 KB of RAM and never touches the host OS filesystem or processes.
#[derive(Debug, Clone)]
pub struct FakeShellSession {
    persona: Arc<PrebakedPersona>,
    user: String,
    cwd: String,
    last_exit_code: i32,
    env_vars: HashMap<String, String>,
    /// Bounded Copy-on-Write file overlay (max 16 files, 8 KB total) so attackers can write
    /// `~/.ssh/authorized_keys` or `/tmp/bot.sh` and read them back realistically.
    cow_files: HashMap<String, String>,
    cow_total_bytes: usize,
    history: Vec<String>,
}

const MAX_COW_FILES: usize = 16;
const MAX_COW_BYTES: usize = 8192;

impl FakeShellSession {
    pub fn new(persona: Arc<PrebakedPersona>, login_user: Option<&str>) -> Self {
        let user = login_user
            .filter(|u| !u.trim().is_empty())
            .map(|u| u.to_string())
            .unwrap_or_else(|| persona.shell_vfs.default_user.clone());
        let home = if user == "root" {
            "/root".to_string()
        } else {
            format!("/home/{}", persona.shell_vfs.default_user)
        };
        let history = persona
            .shell_vfs
            .files
            .get(&format!("/home/{}/.bash_history", persona.shell_vfs.default_user))
            .map(|h| h.lines().map(|l| l.to_string()).collect())
            .unwrap_or_default();

        let mut env_vars = HashMap::new();
        env_vars.insert("USER".to_string(), user.clone());
        env_vars.insert("LOGNAME".to_string(), user.clone());
        env_vars.insert("HOME".to_string(), home.clone());
        env_vars.insert("HOSTNAME".to_string(), persona.hostname.clone());
        env_vars.insert("SHELL".to_string(), "/bin/bash".to_string());
        env_vars.insert("TERM".to_string(), "xterm-256color".to_string());
        env_vars.insert(
            "PATH".to_string(),
            "/opt/conda/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                .to_string(),
        );
        env_vars.insert(
            "CUDA_VISIBLE_DEVICES".to_string(),
            "0,1,2,3,4,5,6,7".to_string(),
        );

        Self {
            persona,
            user,
            cwd: home,
            last_exit_code: 0,
            env_vars,
            cow_files: HashMap::new(),
            cow_total_bytes: 0,
            history,
        }
    }

    pub fn welcome_banner(&self) -> String {
        self.persona.shell_vfs.motd.clone()
    }

    pub fn prompt(&self) -> String {
        let home_prefix = if self.user == "root" {
            "/root".to_string()
        } else {
            format!("/home/{}", self.persona.shell_vfs.default_user)
        };
        let display_cwd = if self.cwd == home_prefix {
            "~".to_string()
        } else if let Some(rel) = self.cwd.strip_prefix(&format!("{home_prefix}/")) {
            format!("~/{rel}")
        } else {
            self.cwd.clone()
        };
        let symbol = if self.user == "root" { "#" } else { "$" };
        format!("{}@{}:{}{} ", self.user, self.persona.hostname, display_cwd, symbol)
    }

    pub fn history(&self) -> &[String] {
        &self.history
    }

    pub fn cow_files(&self) -> &HashMap<String, String> {
        &self.cow_files
    }

    /// Execute a full command line (supports `;`, `&&`, pipes `|`, env expansion `$VAR`, and `>` / `>>` redirection).
    pub fn execute_line(&mut self, raw_line: &str) -> ShellExecResult {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            return ShellExecResult {
                output: String::new(),
                delay_ms: 0,
                captured_indicators: Vec::new(),
                should_exit: false,
            };
        }

        self.history.push(line.to_string());

        let mut combined_output = Vec::new();
        let mut total_delay_ms = 0u64;
        let mut captured_indicators = Vec::new();
        let mut should_exit = false;

        for subcmd in split_chained_commands(line) {
            let subcmd = subcmd.trim();
            if subcmd.is_empty() {
                continue;
            }
            let res = self.execute_pipeline_and_redirection(subcmd);
            if !res.output.is_empty() {
                combined_output.push(res.output);
            }
            total_delay_ms = total_delay_ms.saturating_add(res.delay_ms);
            captured_indicators.extend(res.captured_indicators);
            if res.should_exit {
                should_exit = true;
                break;
            }
        }

        let mut final_output = combined_output.join("\n");
        if !final_output.is_empty() && !final_output.ends_with('\n') {
            final_output.push('\n');
        }

        ShellExecResult {
            output: final_output,
            delay_ms: total_delay_ms.min(8000),
            captured_indicators,
            should_exit,
        }
    }

    fn execute_pipeline_and_redirection(&mut self, cmd_line: &str) -> ShellExecResult {
        let cleaned = cmd_line
            .replace("2>&1", "")
            .replace("2>/dev/null", "")
            .replace("&>/dev/null", "");
        let cleaned = cleaned.trim();

        let (pipeline_part, redirect_target) = parse_redirection(cleaned);

        let stages: Vec<&str> = pipeline_part.split('|').map(|s| s.trim()).collect();
        if stages.is_empty() {
            return ShellExecResult {
                output: String::new(),
                delay_ms: 0,
                captured_indicators: Vec::new(),
                should_exit: false,
            };
        }

        let expanded_first = self.expand_variables(stages[0]);
        let mut res = self.execute_single(&expanded_first, None);

        for &stage in &stages[1..] {
            let expanded_stage = self.expand_variables(stage);
            let next_res = self.execute_single(&expanded_stage, Some(&res.output));
            res.output = next_res.output;
            res.delay_ms = res.delay_ms.saturating_add(next_res.delay_ms);
            res.captured_indicators.extend(next_res.captured_indicators);
            if next_res.should_exit {
                res.should_exit = true;
                break;
            }
        }

        if let Some((target_file, is_append)) = redirect_target {
            let resolved = self.resolve_path(target_file);
            if resolved != "/dev/null" {
                self.write_cow_file(&resolved, &res.output, is_append);
                res.captured_indicators
                    .push(format!("file_write:{resolved} ({} bytes)", res.output.len()));
            }
            res.output.clear();
        }

        res
    }

    fn expand_variables(&self, input: &str) -> String {
        if !input.contains('$') {
            return input.to_string();
        }
        let mut out = input.replace("$?", &self.last_exit_code.to_string());
        out = out.replace("$PWD", &self.cwd);
        out = out.replace("${PWD}", &self.cwd);
        for (k, v) in &self.env_vars {
            out = out.replace(&format!("${{{k}}}"), v);
            out = out.replace(&format!("${k}"), v);
        }
        out
    }

    fn read_vfs_file(&self, resolved_path: &str) -> Option<String> {
        if let Some(cow) = self.cow_files.get(resolved_path) {
            return Some(cow.clone());
        }
        self.persona.shell_vfs.files.get(resolved_path).cloned()
    }

    fn write_cow_file(&mut self, resolved_path: &str, content: &str, append: bool) {
        if self.cow_files.len() >= MAX_COW_FILES && !self.cow_files.contains_key(resolved_path) {
            return;
        }
        let existing = if append {
            self.read_vfs_file(resolved_path).unwrap_or_default()
        } else {
            String::new()
        };
        let mut new_content = if existing.is_empty() {
            content.to_string()
        } else {
            format!("{}\n{}", existing.trim_end_matches('\n'), content)
        };
        if new_content.len() > 2048 {
            new_content.truncate(2048);
        }
        if self.cow_total_bytes + new_content.len() <= MAX_COW_BYTES {
            self.cow_total_bytes += new_content.len();
            self.cow_files.insert(resolved_path.to_string(), new_content);
        }
    }

    fn execute_single(&mut self, cmd_line: &str, stdin_input: Option<&str>) -> ShellExecResult {
        let parts: Vec<&str> = cmd_line.split_whitespace().collect();
        if parts.is_empty() {
            return ShellExecResult {
                output: String::new(),
                delay_ms: 0,
                captured_indicators: Vec::new(),
                should_exit: false,
            };
        }

        let prog = parts[0];
        let args = &parts[1..];

        if !prog.starts_with('/') && prog.contains('=') && args.is_empty() {
            if let Some((k, v)) = prog.split_once('=') {
                self.env_vars
                    .insert(k.to_string(), v.trim_matches('"').trim_matches('\'').to_string());
                self.last_exit_code = 0;
                return ShellExecResult {
                    output: String::new(),
                    delay_ms: 10,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                };
            }
        }

        self.last_exit_code = 0;

        match prog {
            "exit" | "logout" | "quit" => ShellExecResult {
                output: "logout".to_string(),
                delay_ms: 0,
                captured_indicators: Vec::new(),
                should_exit: true,
            },
            "clear" | "reset" => ShellExecResult {
                output: "\x1b[2J\x1b[H".to_string(),
                delay_ms: 10,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "true" | ":" => ShellExecResult {
                output: String::new(),
                delay_ms: 10,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "false" => {
                self.last_exit_code = 1;
                ShellExecResult {
                    output: String::new(),
                    delay_ms: 10,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "id" => {
                let (uid, gid) = if self.user == "root" {
                    (0, 0)
                } else {
                    (1000, 1000)
                };
                ShellExecResult {
                    output: format!(
                        "uid={uid}({user}) gid={gid}({user}) groups={gid}({user}),27(sudo),44(video),998(docker)",
                        user = self.user
                    ),
                    delay_ms: 30,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "whoami" => ShellExecResult {
                output: self.user.clone(),
                delay_ms: 20,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "groups" => ShellExecResult {
                output: format!("{} sudo video docker", self.user),
                delay_ms: 20,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "w" => ShellExecResult {
                output: self.persona.shell_vfs.w_output.clone(),
                delay_ms: 40,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "who" => ShellExecResult {
                output: format!("{} pts/0        2026-11-22 03:12 (10.240.0.5)", self.user),
                delay_ms: 30,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "last" | "lastlog" => ShellExecResult {
                output: self.persona.shell_vfs.last_output.clone(),
                delay_ms: 50,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "hostname" => {
                let out = if args.contains(&"-I") || args.contains(&"-i") {
                    format!("{} 172.17.0.1", self.persona.internal_ip)
                } else if args.contains(&"-f") {
                    format!("{}.internal.corp", self.persona.hostname)
                } else {
                    self.persona.hostname.clone()
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 25,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "hostnamectl" => ShellExecResult {
                output: format!(
                    " Static hostname: {host}\n\
                     \x20      Icon name: computer-server\n\
                     \x20        Chassis: server\n\
                     \x20     Machine ID: 9f4b2c8e1a7d3065b8e2f1c4a9d0731e\n\
                     \x20        Boot ID: 4a1c8e9d2b7410a9f8a7c2e1b4d603f5\n\
                     Operating System: Ubuntu 22.04.3 LTS\n\
                     \x20         Kernel: Linux 5.15.0-91-generic\n\
                     \x20   Architecture: x86-64\n\
                     \x20Hardware Vendor: Supermicro\n\
                     \x20 Hardware Model: AS-8125GS-TNHR",
                    host = self.persona.hostname
                ),
                delay_ms: 45,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "lsb_release" => ShellExecResult {
                output: "No LSB modules are available.\n\
                         Distributor ID:\tUbuntu\n\
                         Description:\tUbuntu 22.04.3 LTS\n\
                         Release:\t22.04\n\
                         Codename:\tjammy"
                    .to_string(),
                delay_ms: 35,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "pwd" => ShellExecResult {
                output: self.cwd.clone(),
                delay_ms: 15,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "uname" => {
                let out = if args.iter().any(|a| a.contains('a')) {
                    self.persona.shell_vfs.kernel_uname.clone()
                } else if args.iter().any(|a| a.contains('r')) {
                    self.persona.shell_vfs.kernel_release.clone()
                } else if args.iter().any(|a| a.contains('n')) {
                    self.persona.hostname.clone()
                } else if args.iter().any(|a| a.contains('m')) {
                    "x86_64".to_string()
                } else {
                    "Linux".to_string()
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 25,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "lscpu" => ShellExecResult {
                output: self.persona.shell_vfs.lscpu_output.clone(),
                delay_ms: 40,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "lspci" => ShellExecResult {
                output: self.persona.shell_vfs.lspci_output.clone(),
                delay_ms: 50,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "lsblk" => ShellExecResult {
                output: self.persona.shell_vfs.lsblk_output.clone(),
                delay_ms: 40,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "mount" | "findmnt" => ShellExecResult {
                output: self.persona.shell_vfs.mount_output.clone(),
                delay_ms: 35,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "dmesg" => ShellExecResult {
                output: self.persona.shell_vfs.dmesg_output.clone(),
                delay_ms: 60,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "nvidia-smi" => {
                let out = if args.contains(&"-L") {
                    "GPU 0: NVIDIA H100 80GB HBM3 (UUID: GPU-9f4b2c8e-1a7d-3065-b8e2-f1c4a9d00000)\n\
                     GPU 1: NVIDIA H100 80GB HBM3 (UUID: GPU-9f4b2c8e-1a7d-3065-b8e2-f1c4a9d00001)"
                        .to_string()
                } else {
                    self.persona.shell_vfs.nvidia_smi_output.clone()
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 280,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "ps" => ShellExecResult {
                output: self.persona.shell_vfs.ps_aux_output.clone(),
                delay_ms: 80,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "top" | "htop" => ShellExecResult {
                output: self.persona.shell_vfs.top_output.clone(),
                delay_ms: 150,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "pgrep" => {
                let pattern = args.last().copied().unwrap_or("python");
                let mut pids = Vec::new();
                for line in self.persona.shell_vfs.ps_aux_output.lines().skip(1) {
                    if line.contains(pattern) {
                        if let Some(pid) = line.split_whitespace().nth(1) {
                            pids.push(pid);
                        }
                    }
                }
                ShellExecResult {
                    output: pids.join("\n"),
                    delay_ms: 40,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "systemctl" => {
                let out = if args.contains(&"status") {
                    let unit = args.last().copied().unwrap_or("ssh.service");
                    format!(
                        "● {unit} - Production Daemon ({host})\n\
                         \x20    Loaded: loaded (/lib/systemd/system/{unit}; enabled; vendor preset: enabled)\n\
                         \x20    Active: active (running) since Wed 2026-10-12 03:14:00 UTC; 41 days ago",
                        host = self.persona.hostname
                    )
                } else {
                    self.persona.shell_vfs.systemctl_output.clone()
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 70,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "service" => {
                let svc = args.first().copied().unwrap_or("ssh");
                ShellExecResult {
                    output: format!(" * {svc} is running"),
                    delay_ms: 50,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "journalctl" => ShellExecResult {
                output: format!(
                    "Nov 22 03:12:44 {host} sshd[19402]: Accepted publickey for {user} from 10.240.0.5 port 54120 ssh2\n\
                     Nov 22 04:00:01 {host} CRON[19810]: ({user}) CMD (/usr/bin/python3 /opt/deploy/sync_vault.py)",
                    host = self.persona.hostname,
                    user = self.user
                ),
                delay_ms: 80,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "netstat" | "ss" => ShellExecResult {
                output: self.persona.shell_vfs.netstat_output.clone(),
                delay_ms: 70,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "ip" => {
                let out = if args.first().copied() == Some("route")
                    || args.first().copied() == Some("r")
                {
                    self.persona.shell_vfs.ip_route_output.clone()
                } else {
                    self.persona.shell_vfs.ip_addr_output.clone()
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 50,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "ifconfig" => ShellExecResult {
                output: self.persona.shell_vfs.ip_addr_output.clone(),
                delay_ms: 50,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "route" => ShellExecResult {
                output: self.persona.shell_vfs.ip_route_output.clone(),
                delay_ms: 40,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "iptables" => ShellExecResult {
                output: self.persona.shell_vfs.iptables_output.clone(),
                delay_ms: 60,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "uptime" => ShellExecResult {
                output: " 14:55:02 up 41 days, 18:12,  1 user,  load average: 1.42, 1.38, 1.29"
                    .to_string(),
                delay_ms: 30,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "date" => ShellExecResult {
                output: "Sun Nov 22 14:55:02 UTC 2026".to_string(),
                delay_ms: 20,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "free" => ShellExecResult {
                output: "               total        used        free      shared  buff/cache   available\n\
                         Mem:           504Gi       121Gi       297Gi       412Mi        84Gi       379Gi\n\
                         Swap:          8.0Gi          0B       8.0Gi"
                    .to_string(),
                delay_ms: 30,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "df" => ShellExecResult {
                output: "Filesystem      Size  Used Avail Use% Mounted on\n\
                         /dev/nvme0n1p2  1.8T  760G  1.1T  42% /\n\
                         /dev/nvme1n1p1  7.3T  4.1T  3.2T  57% /mnt/llm_checkpoints"
                    .to_string(),
                delay_ms: 40,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            "env" | "printenv" => {
                let mut lines: Vec<String> = self
                    .env_vars
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect();
                lines.sort();
                ShellExecResult {
                    output: lines.join("\n"),
                    delay_ms: 30,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "export" => {
                for arg in args {
                    if let Some((k, v)) = arg.split_once('=') {
                        self.env_vars.insert(
                            k.to_string(),
                            v.trim_matches('"').trim_matches('\'').to_string(),
                        );
                    }
                }
                ShellExecResult {
                    output: String::new(),
                    delay_ms: 15,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "history" => {
                let out = self
                    .history
                    .iter()
                    .enumerate()
                    .map(|(i, cmd)| format!("{:5}  {}", i + 1, cmd))
                    .collect::<Vec<_>>()
                    .join("\n");
                ShellExecResult {
                    output: out,
                    delay_ms: 30,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "crontab" => {
                let out = if args.contains(&"-l") {
                    self.persona.shell_vfs.crontab_output.clone()
                } else {
                    "crontab: no changes made to crontab".to_string()
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 45,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "sudo" => {
                if args.contains(&"-l") {
                    return ShellExecResult {
                        output: self.persona.shell_vfs.sudo_l_output.clone(),
                        delay_ms: 120,
                        captured_indicators: Vec::new(),
                        should_exit: false,
                    };
                }
                if args.iter().any(|a| a.contains("sync_vault.py")) {
                    return ShellExecResult {
                        output: format!(
                            "[vault-sync] Authenticating to Vault cluster (10.240.0.10:8200)...\n\
                             [vault-sync] Loaded AWS key {} and export endpoint {} (X-Api-Key: {}).\n\
                             [vault-sync] Completed key rotation heartbeat.",
                            self.persona.canary_aws_access_key,
                            self.persona.canary_endpoint_path,
                            self.persona.canary_api_key,
                        ),
                        delay_ms: 900,
                        captured_indicators: Vec::new(),
                        should_exit: false,
                    };
                }
                if args.contains(&"docker") {
                    return ShellExecResult {
                        output: self.persona.shell_vfs.docker_ps_output.clone(),
                        delay_ms: 120,
                        captured_indicators: Vec::new(),
                        should_exit: false,
                    };
                }
                ShellExecResult {
                    output: format!(
                        "[sudo] password for {}: \nsudo: PAM authentication service temporarily busy",
                        self.user
                    ),
                    delay_ms: 2000,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "docker" => {
                let sub = args.first().copied().unwrap_or("ps");
                let out = match sub {
                    "images" | "image" => self.persona.shell_vfs.docker_images_output.clone(),
                    _ => self.persona.shell_vfs.docker_ps_output.clone(),
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 90,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "kubectl" => {
                let out = if args.contains(&"secrets") || args.contains(&"secret") {
                    self.persona.shell_vfs.kubectl_secrets_output.clone()
                } else {
                    self.persona.shell_vfs.kubectl_pods_output.clone()
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 150,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "python3" | "python" => {
                if args.contains(&"--version") || args.contains(&"-V") {
                    return ShellExecResult {
                        output: "Python 3.10.12".to_string(),
                        delay_ms: 30,
                        captured_indicators: Vec::new(),
                        should_exit: false,
                    };
                }
                let indicators = extract_urls_and_ips(cmd_line);
                ShellExecResult {
                    output: String::new(),
                    delay_ms: 150,
                    captured_indicators: indicators,
                    should_exit: false,
                }
            }
            "which" | "whereis" => {
                let target = args.first().copied().unwrap_or("bash");
                ShellExecResult {
                    output: format!("/usr/bin/{target}"),
                    delay_ms: 20,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "find" => {
                let start = args
                    .first()
                    .copied()
                    .filter(|a| !a.starts_with('-'))
                    .unwrap_or(&self.cwd);
                let resolved = self.resolve_path(start);
                let mut paths: Vec<String> = self
                    .persona
                    .shell_vfs
                    .files
                    .keys()
                    .chain(self.cow_files.keys())
                    .filter(|k| k.starts_with(&resolved) || resolved == "/")
                    .cloned()
                    .collect();
                paths.sort();
                paths.dedup();
                ShellExecResult {
                    output: paths.join("\n"),
                    delay_ms: 90,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "cd" => {
                let target = args.first().copied().unwrap_or("~");
                let resolved = self.resolve_path(target);
                self.cwd = resolved.clone();
                self.env_vars.insert("PWD".to_string(), resolved);
                ShellExecResult {
                    output: String::new(),
                    delay_ms: 15,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "ls" | "dir" | "ll" => {
                let show_long =
                    prog == "ll" || args.iter().any(|a| a.starts_with('-') && a.contains('l'));
                let show_all =
                    prog == "ll" || args.iter().any(|a| a.starts_with('-') && a.contains('a'));
                let target_arg = args
                    .iter()
                    .copied()
                    .find(|a| !a.starts_with('-'))
                    .unwrap_or(&self.cwd);
                let resolved = self.resolve_path(target_arg);

                let mut entries = self
                    .persona
                    .shell_vfs
                    .directories
                    .get(&resolved)
                    .cloned()
                    .unwrap_or_default();

                let prefix = if resolved == "/" {
                    "/".to_string()
                } else {
                    format!("{resolved}/")
                };
                for cow_path in self.cow_files.keys() {
                    if let Some(rel) = cow_path.strip_prefix(&prefix) {
                        if !rel.contains('/') && !entries.contains(&rel.to_string()) {
                            entries.push(rel.to_string());
                        }
                    }
                }

                if !show_all {
                    entries.retain(|e| !e.starts_with('.'));
                }
                entries.sort();

                let output = if show_long {
                    let mut lines = vec![format!("total {}", (entries.len() + 2) * 4)];
                    for entry in entries {
                        let full = if resolved == "/" {
                            format!("/{entry}")
                        } else {
                            format!("{resolved}/{entry}")
                        };
                        let is_dir = self.persona.shell_vfs.directories.contains_key(&full);
                        let perms = if is_dir { "drwxr-xr-x" } else { "-rw-r-----" };
                        let size = self
                            .read_vfs_file(&full)
                            .map(|c| c.len())
                            .unwrap_or(4096);
                        lines.push(format!(
                            "{perms} 1 {user} {user} {size:>5} Nov 21 19:40 {entry}",
                            user = self.user
                        ));
                    }
                    lines.join("\n")
                } else {
                    entries.join("  ")
                };
                ShellExecResult {
                    output,
                    delay_ms: 35,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "cat" | "tac" | "nl" | "less" | "more" => {
                let file_args: Vec<&str> =
                    args.iter().copied().filter(|a| !a.starts_with('-')).collect();
                if file_args.is_empty() {
                    return ShellExecResult {
                        output: stdin_input.unwrap_or("").to_string(),
                        delay_ms: 15,
                        captured_indicators: Vec::new(),
                        should_exit: false,
                    };
                }
                let mut outputs = Vec::new();
                let mut indicators = Vec::new();
                for target in file_args {
                    let resolved = self.resolve_path(target);
                    indicators.push(format!("file_read:{resolved}"));
                    if resolved == "/etc/shadow" && self.user != "root" {
                        self.last_exit_code = 1;
                        outputs.push("cat: /etc/shadow: Permission denied".to_string());
                        continue;
                    }
                    match self.read_vfs_file(&resolved) {
                        Some(content) => outputs.push(content),
                        None => {
                            self.last_exit_code = 1;
                            outputs.push(format!("{prog}: {target}: No such file or directory"));
                        }
                    }
                }
                ShellExecResult {
                    output: outputs.join("\n"),
                    delay_ms: 40,
                    captured_indicators: indicators,
                    should_exit: false,
                }
            }
            "grep" | "egrep" | "fgrep" => {
                let case_insensitive =
                    args.iter().any(|a| a.starts_with('-') && a.contains('i'));
                let non_flags: Vec<&str> =
                    args.iter().copied().filter(|a| !a.starts_with('-')).collect();
                let pattern = non_flags
                    .first()
                    .copied()
                    .unwrap_or("")
                    .trim_matches('"')
                    .trim_matches('\'');
                let source_text = if let Some(file_arg) = non_flags.get(1) {
                    let resolved = self.resolve_path(file_arg);
                    self.read_vfs_file(&resolved).unwrap_or_default()
                } else {
                    stdin_input.unwrap_or("").to_string()
                };
                let pat_cmp = if case_insensitive {
                    pattern.to_ascii_lowercase()
                } else {
                    pattern.to_string()
                };
                let matched: Vec<&str> = source_text
                    .lines()
                    .filter(|line| {
                        let hay = if case_insensitive {
                            line.to_ascii_lowercase()
                        } else {
                            (*line).to_string()
                        };
                        hay.contains(&pat_cmp)
                    })
                    .collect();
                ShellExecResult {
                    output: matched.join("\n"),
                    delay_ms: 25,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "base64" => {
                let decode = args.contains(&"-d") || args.contains(&"--decode");
                let text = stdin_input.unwrap_or("").trim();
                let out = if decode {
                    base64::engine::general_purpose::STANDARD
                        .decode(text)
                        .map(|b| String::from_utf8_lossy(&b).into_owned())
                        .unwrap_or_else(|_| "base64: invalid input".to_string())
                } else {
                    base64::engine::general_purpose::STANDARD.encode(text.as_bytes())
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 20,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "sha256sum" | "md5sum" => {
                let text = stdin_input.unwrap_or("");
                let mut hasher = Sha256::new();
                hasher.update(text.as_bytes());
                let digest = hasher.finalize();
                let hex_str: String = digest.iter().map(|b| format!("{b:02x}")).collect();
                let out = if prog == "md5sum" {
                    format!("{}  -", &hex_str[..32])
                } else {
                    format!("{hex_str}  -")
                };
                ShellExecResult {
                    output: out,
                    delay_ms: 25,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
            "wget" | "curl" | "tftp" | "scp" | "sftp" | "fetch" | "nc" | "netcat" | "ncat"
            | "socat" => {
                let indicators = extract_urls_and_ips(cmd_line);
                let target_url = indicators
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "http://remote-payload/bin".to_string());

                if let Some(out_pos) = args.iter().position(|&a| a == "-O" || a == "-o") {
                    if let Some(&out_file) = args.get(out_pos + 1) {
                        let resolved = self.resolve_path(out_file);
                        self.write_cow_file(&resolved, "#!/bin/elf\n", false);
                    }
                }

                ShellExecResult {
                    output: format!(
                        "--  Resolving payload host ({target_url})...\n\
                         Connecting... connected.\n\
                         HTTP request sent, awaiting response... 200 OK\n\
                         Length: 1843200 (1.8M) [application/octet-stream]\n\
                         Saving to:Payload...\n\
                         100%[======================================>] 1,843,200   412KB/s   in 4.4s\n\
                         Saved (1843200 bytes)."
                    ),
                    delay_ms: 2200,
                    captured_indicators: if indicators.is_empty() {
                        vec![format!("net_tool:{cmd_line}")]
                    } else {
                        indicators
                    },
                    should_exit: false,
                }
            }
            "echo" | "printf" => ShellExecResult {
                output: args.join(" ").trim_matches('"').trim_matches('\'').to_string(),
                delay_ms: 15,
                captured_indicators: Vec::new(),
                should_exit: false,
            },
            _ => {
                if prog.starts_with("./")
                    || prog.starts_with("/tmp/")
                    || prog.starts_with("/var/tmp/")
                    || prog == "sh"
                    || prog == "bash"
                {
                    let mut indicators = extract_urls_and_ips(cmd_line);
                    indicators.push(format!("exec_payload:{cmd_line}"));
                    return ShellExecResult {
                        output: format!(
                            "{prog}: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found (required by {prog})\n\
                             Hint: Host {host} uses Ubuntu 22.04 glibc 2.35; compile with -static or glibc<=2.35",
                            host = self.persona.hostname
                        ),
                        delay_ms: 1500,
                        captured_indicators: indicators,
                        should_exit: false,
                    };
                }

                self.last_exit_code = 127;
                ShellExecResult {
                    output: format!("bash: {prog}: command not found"),
                    delay_ms: 40,
                    captured_indicators: Vec::new(),
                    should_exit: false,
                }
            }
        }
    }

    pub fn resolve_path(&self, raw: &str) -> String {
        let home = if self.user == "root" {
            "/root".to_string()
        } else {
            format!("/home/{}", self.persona.shell_vfs.default_user)
        };
        let expanded = if raw == "~" {
            home
        } else if let Some(stripped) = raw.strip_prefix("~/") {
            format!("{home}/{stripped}")
        } else if raw.starts_with('/') {
            raw.to_string()
        } else if self.cwd == "/" {
            format!("/{raw}")
        } else {
            format!("{}/{}", self.cwd.trim_end_matches('/'), raw)
        };

        let mut stack = Vec::new();
        for comp in expanded.split('/') {
            match comp {
                "" | "." => {}
                ".." => {
                    stack.pop();
                }
                other => stack.push(other),
            }
        }
        if stack.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", stack.join("/"))
        }
    }
}

fn split_chained_commands(line: &str) -> Vec<&str> {
    let mut result = Vec::new();
    for segment in line.split(';') {
        for sub in segment.split("&&") {
            result.push(sub);
        }
    }
    result
}

fn parse_redirection(cmd: &str) -> (&str, Option<(&str, bool)>) {
    if let Some((left, right)) = cmd.split_once(">>") {
        let target = right
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches('"')
            .trim_matches('\'');
        if !target.is_empty() {
            return (left.trim(), Some((target, true)));
        }
    }
    if let Some((left, right)) = cmd.split_once('>') {
        let target = right
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches('"')
            .trim_matches('\'');
        if !target.is_empty() {
            return (left.trim(), Some((target, false)));
        }
    }
    (cmd, None)
}

fn extract_urls_and_ips(cmd_line: &str) -> Vec<String> {
    let mut found = Vec::new();
    for token in cmd_line.split_whitespace() {
        let cleaned = token.trim_matches(|c| c == '"' || c == '\'' || c == ';');
        if cleaned.starts_with("http://")
            || cleaned.starts_with("https://")
            || cleaned.starts_with("ftp://")
            || cleaned.starts_with("tftp://")
            || cleaned.contains("/dev/tcp/")
        {
            found.push(format!("c2_url:{cleaned}"));
        }
    }
    found
}
