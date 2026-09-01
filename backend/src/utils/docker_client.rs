use std::{env, time::Instant};

use bollard::{
    container::LogOutput,
    exec::{CreateExecOptions, StartExecResults},
};
use futures_util::StreamExt;
use serde_json::Value;

use crate::{
    AppState,
    crowdsec_api::read_lapi_decisions,
    models::models::{ActiveBan, Alert},
    utils::normaliser::{normalize_alert_payload, normalize_decisions_as_bans, truncate_line},
};

pub async fn read_runtime_revision(state: &AppState) -> Result<(String, String), String> {
    let hostname = env::var("HOSTNAME").map_err(|_| "HOSTNAME is not set".to_string())?;

    let docker = state
        .docker_client
        .as_ref()
        .ok_or_else(|| "Docker is unavailable; running in demo mode".to_string())?;

    let container = docker
        .inspect_container(&hostname, None)
        .await
        .map_err(|e| format!("Docker inspection failed: {e}"))?;

    let config = container
        .config
        .as_ref()
        .ok_or_else(|| "Container configuration is unavailable".to_string())?;

    let image = config
        .image
        .clone()
        .ok_or_else(|| "Container image is unavailable".to_string())?;

    let revision = config
        .labels
        .as_ref()
        .and_then(|labels| labels.get("org.opencontainers.image.revision").cloned())
        .ok_or_else(|| "The running image does not expose a Git revision label".to_string())?;

    Ok((image, revision))
}

pub async fn read_cscli_alerts(state: &AppState) -> Option<Vec<Alert>> {
    let docker = state.docker_client.as_ref()?;

    let container = if state.config.crowdsec_container.is_empty() {
        crate::warn!("CrowdSec container is not configured");
        return None;
    } else {
        state.config.crowdsec_container.as_str()
    };

    let args = ["cscli", "alerts", "list", "-o", "json", "--limit", "0"];

    if args.is_empty() {
        crate::warn!("cscli command contains no arguments");
        return None;
    }

    let command_line = args.join(" ");
    let started = Instant::now();

    crate::debug!(
        container = %container,
        command = %command_line,
        "starting cscli alerts command"
    );

    let exec = match docker
        .create_exec(
            container,
            CreateExecOptions {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(args.to_vec()),
                ..Default::default()
            },
        )
        .await
    {
        Ok(exec) => exec,
        Err(err) => {
            crate::warn!(
                container = %container,
                error = %err,
                "failed to create cscli alerts exec"
            );
            return None;
        }
    };

    let output = match docker.start_exec(&exec.id, None).await {
        Ok(output) => output,
        Err(err) => {
            crate::warn!(
                container = %container,
                error = %err,
                "failed to start cscli alerts exec"
            );
            return None;
        }
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    match output {
        StartExecResults::Attached { mut output, .. } => {
            while let Some(result) = output.next().await {
                match result {
                    Ok(LogOutput::StdOut { message }) => {
                        stdout.extend_from_slice(&message);
                    }
                    Ok(LogOutput::StdErr { message }) => {
                        stderr.extend_from_slice(&message);
                    }
                    Ok(_) => {}
                    Err(err) => {
                        crate::warn!(
                            container = %container,
                            error = %err,
                            "error reading cscli alerts output"
                        );
                        return None;
                    }
                }
            }
        }
        StartExecResults::Detached => {
            crate::warn!(
                container = %container,
                "cscli alerts exec unexpectedly started in detached mode"
            );
            return None;
        }
    }

    let exec_inspect = match docker.inspect_exec(&exec.id).await {
        Ok(result) => result,
        Err(err) => {
            crate::warn!(
                container = %container,
                error = %err,
                "failed to inspect cscli alerts exec"
            );
            return None;
        }
    };

    let exit_code = exec_inspect.exit_code.unwrap_or(-1);

    crate::debug!(
        container = %container,
        command = %command_line,
        status = exit_code,
        stdout_bytes = stdout.len(),
        stderr_bytes = stderr.len(),
        elapsed_ms = started.elapsed().as_millis(),
        "cscli alerts command completed"
    );

    let stdout_text = String::from_utf8_lossy(&stdout);
    let stderr_text = String::from_utf8_lossy(&stderr);

    crate::debug!(
        command = %command_line,
        stdout_preview = %truncate_line(&stdout_text, 1000),
        stderr_preview = %truncate_line(&stderr_text, 1000),
        "cscli alerts command output"
    );

    if exit_code != 0 {
        crate::warn!(
            status = exit_code,
            stderr = %stderr_text,
            "cscli alerts returned an error"
        );
        return None;
    }

    let payload: Value = match serde_json::from_slice(&stdout) {
        Ok(payload) => payload,
        Err(err) => {
            crate::warn!(
                error = %err,
                output = %stdout_text.trim(),
                "cscli alerts returned invalid JSON"
            );
            return None;
        }
    };

    Some(normalize_alert_payload(&payload, "cscli"))
}

pub async fn read_active_bans(state: &AppState) -> Option<Vec<ActiveBan>> {
    crate::debug!(
        lapi_configured = !state.config.lapi_api_key.is_empty(),
        "loading active decisions"
    );

    if !state.config.lapi_api_key.is_empty() {
        if let Some(decisions) = read_lapi_decisions(state).await {
            crate::info!(
                source = "lapi",
                decisions = decisions.len(),
                "active decisions loaded"
            );
            return Some(decisions);
        }

        crate::warn!("LAPI decisions request failed; falling back to cscli");
    }

    let docker = state.docker_client.as_ref().or_else(|| {
        crate::warn!("Docker is unavailable; cannot run cscli decisions");
        None
    })?;

    let container = if state.config.crowdsec_container.is_empty() {
        crate::warn!("CrowdSec container is not configured");
        return None;
    } else {
        state.config.crowdsec_container.as_str()
    };

    let args = ["cscli", "decisions", "list", "-o", "json", "--limit", "0"];

    let command_line = args.join(" ");
    let started = Instant::now();

    crate::debug!(
        container = %container,
        command = %command_line,
        "starting cscli decisions command"
    );

    let exec = match docker
        .create_exec(
            container,
            CreateExecOptions {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(args.to_vec()),
                ..Default::default()
            },
        )
        .await
    {
        Ok(exec) => exec,
        Err(err) => {
            crate::warn!(
                container = %container,
                error = %err,
                "failed to create cscli decisions exec"
            );
            return None;
        }
    };

    let output = match docker.start_exec(&exec.id, None).await {
        Ok(output) => output,
        Err(err) => {
            crate::warn!(
                container = %container,
                error = %err,
                "failed to start cscli decisions exec"
            );
            return None;
        }
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    match output {
        StartExecResults::Attached { mut output, .. } => {
            while let Some(result) = output.next().await {
                match result {
                    Ok(LogOutput::StdOut { message }) => {
                        stdout.extend_from_slice(&message);
                    }
                    Ok(LogOutput::StdErr { message }) => {
                        stderr.extend_from_slice(&message);
                    }
                    Ok(_) => {}
                    Err(err) => {
                        crate::warn!(
                            container = %container,
                            error = %err,
                            "error reading cscli decisions output"
                        );
                        return None;
                    }
                }
            }
        }
        StartExecResults::Detached => {
            crate::warn!(
                container = %container,
                "cscli decisions exec unexpectedly started in detached mode"
            );
            return None;
        }
    }

    let exec_inspect = match docker.inspect_exec(&exec.id).await {
        Ok(result) => result,
        Err(err) => {
            crate::warn!(
                container = %container,
                error = %err,
                "failed to inspect cscli decisions exec"
            );
            return None;
        }
    };

    let exit_code = exec_inspect.exit_code.unwrap_or(-1);

    crate::debug!(
        container = %container,
        command = %command_line,
        status = exit_code,
        stdout_bytes = stdout.len(),
        stderr_bytes = stderr.len(),
        elapsed_ms = started.elapsed().as_millis(),
        "cscli decisions command completed"
    );

    let stdout_text = String::from_utf8_lossy(&stdout);
    let stderr_text = String::from_utf8_lossy(&stderr);

    crate::debug!(
        command = %command_line,
        stdout_preview = %truncate_line(&stdout_text, 1000),
        stderr_preview = %truncate_line(&stderr_text, 1000),
        "cscli decisions command output"
    );

    if exit_code != 0 {
        crate::warn!(
            status = exit_code,
            stderr = %stderr_text,
            "cscli decisions returned an error"
        );
        return None;
    }

    let payload: Value = match serde_json::from_slice(&stdout) {
        Ok(payload) => payload,
        Err(err) => {
            crate::warn!(
                error = %err,
                output = %stdout_text.trim(),
                "cscli decisions returned invalid JSON"
            );
            return None;
        }
    };

    let bans = normalize_decisions_as_bans(&payload);

    crate::info!(
        container = %container,
        decisions = bans.len(),
        "cscli decisions loaded"
    );

    Some(bans)
}

pub async fn read_cscli_ip_details(state: &AppState, ip: &str) -> (String, String, String) {
    let docker = match state.docker_client.as_ref() {
        Some(docker) => docker,
        None => {
            let error = "Docker is unavailable".to_string();

            crate::error!(
                ip = %ip,
                error = %error,
                "unable to run cscli IP details command"
            );

            return (String::new(), String::new(), error);
        }
    };

    let container = if state.config.crowdsec_container.is_empty() {
        let error = "CrowdSec container is not configured".to_string();

        crate::error!(
            ip = %ip,
            error = %error,
            "unable to run cscli IP details command"
        );

        return (String::new(), String::new(), error);
    } else {
        state.config.crowdsec_container.as_str()
    };

    let args = [
        "cscli", "alerts", "list", "-o", "human", "--ip", ip, "--limit", "0",
    ];

    let command_line = args.join(" ");
    let started = Instant::now();

    crate::debug!(
        ip = %ip,
        container = %container,
        command = %command_line,
        "starting cscli IP details command"
    );

    let exec = match docker
        .create_exec(
            container,
            CreateExecOptions {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(args.to_vec()),
                ..Default::default()
            },
        )
        .await
    {
        Ok(exec) => exec,
        Err(err) => {
            let error = format!("failed to create cscli exec: {err}");

            crate::error!(
                ip = %ip,
                container = %container,
                command = %command_line,
                error = %error,
                elapsed_ms = started.elapsed().as_millis(),
                "unable to start cscli IP details command"
            );

            return (String::new(), command_line, error);
        }
    };

    let output = match docker.start_exec(&exec.id, None).await {
        Ok(output) => output,
        Err(err) => {
            let error = format!("failed to start cscli exec: {err}");

            crate::error!(
                ip = %ip,
                container = %container,
                command = %command_line,
                error = %error,
                elapsed_ms = started.elapsed().as_millis(),
                "unable to start cscli IP details command"
            );

            return (String::new(), command_line, error);
        }
    };

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();

    match output {
        StartExecResults::Attached { mut output, .. } => {
            while let Some(result) = output.next().await {
                match result {
                    Ok(LogOutput::StdOut { message }) => {
                        stdout.extend_from_slice(&message);
                    }
                    Ok(LogOutput::StdErr { message }) => {
                        stderr.extend_from_slice(&message);
                    }
                    Ok(_) => {}
                    Err(err) => {
                        let error = format!("failed to read cscli output: {err}");

                        crate::error!(
                            ip = %ip,
                            container = %container,
                            command = %command_line,
                            error = %error,
                            elapsed_ms = started.elapsed().as_millis(),
                            "unable to read cscli IP details output"
                        );

                        return (String::new(), command_line, error);
                    }
                }
            }
        }
        StartExecResults::Detached => {
            let error = "cscli exec unexpectedly started in detached mode".to_string();

            crate::error!(
                ip = %ip,
                container = %container,
                command = %command_line,
                error = %error,
                elapsed_ms = started.elapsed().as_millis(),
                "unable to read cscli IP details output"
            );

            return (String::new(), command_line, error);
        }
    }

    let exec_inspect = match docker.inspect_exec(&exec.id).await {
        Ok(result) => result,
        Err(err) => {
            let error = format!("failed to inspect cscli exec: {err}");

            crate::error!(
                ip = %ip,
                container = %container,
                command = %command_line,
                error = %error,
                elapsed_ms = started.elapsed().as_millis(),
                "unable to determine cscli IP details command status"
            );

            return (String::new(), command_line, error);
        }
    };

    let exit_code = exec_inspect.exit_code.unwrap_or(-1);

    let text = String::from_utf8(stdout)
        .unwrap_or_default()
        .trim()
        .to_string();

    let stderr_text = String::from_utf8(stderr).unwrap_or_else(|_| "cscli failed".to_string());

    crate::debug!(
        ip = %ip,
        container = %container,
        command = %command_line,
        status = exit_code,
        stdout_bytes = text.len(),
        stderr_bytes = stderr_text.len(),
        elapsed_ms = started.elapsed().as_millis(),
        "cscli IP details command completed"
    );

    if exit_code == 0 {
        (text, command_line, String::new())
    } else {
        crate::warn!(
            ip = %ip,
            container = %container,
            command = %command_line,
            status = exit_code,
            stderr = %stderr_text,
            elapsed_ms = started.elapsed().as_millis(),
            "cscli IP details command failed"
        );

        (String::new(), command_line, stderr_text)
    }
}
