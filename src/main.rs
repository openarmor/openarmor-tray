use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tray_item::{IconSource, TrayItem};
use std::process::Command;
use notify_rust::Notification;

enum Message {
    Quit,
    CheckAgents,
    UpdateStatus,
}

enum Icon {
    NoAgents,
    OssecOnly,
    OsqueryOnly,
    BothAgents,
}

impl Icon {
    fn resource(&self) -> IconSource {
        match self {
            Self::NoAgents => IconSource::Resource("icon-no-agents"),
            Self::OssecOnly => IconSource::Resource("icon-ossec-only"),
            Self::OsqueryOnly => IconSource::Resource("icon-osquery-only"),
            Self::BothAgents => IconSource::Resource("icon-both-agents"),
        }
    }
}

#[derive(PartialEq, Clone)]
struct AgentStatus {
    ossec_installed: bool,
    ossec_running: bool,
    osquery_installed: bool,
    osquery_running: bool,
}

fn check_agent_installed(agent: &str) -> bool {
    let output = Command::new("cmd")
        .args(&["/C", "where", agent])
        .output()
        .expect("Failed to execute command");
    
    output.status.success()
}

fn check_process_running(process: &str) -> bool {
    let output = Command::new("tasklist")
        .output()
        .expect("Failed to execute command");

    String::from_utf8_lossy(&output.stdout).contains(process)
}

fn get_current_status() -> AgentStatus {
    let ossec_installed = check_agent_installed("ossec-agent.exe") || check_agent_installed("wazuh-agent.exe");
    let osquery_installed = check_agent_installed("osqueryd.exe");
    let ossec_running = check_process_running("ossec-agent.exe") || check_process_running("wazuh-agent.exe");
    let osquery_running = check_process_running("osqueryd.exe");

    AgentStatus {
        ossec_installed,
        ossec_running,
        osquery_installed,
        osquery_running,
    }
}

fn get_icon(status: &AgentStatus) -> Icon {
    match (status.ossec_installed && status.ossec_running, status.osquery_installed && status.osquery_running) {
        (true, true) => Icon::BothAgents,
        (true, false) => Icon::OssecOnly,
        (false, true) => Icon::OsqueryOnly,
        (false, false) => Icon::NoAgents,
    }
}

fn send_notification(title: &str, body: &str) -> Result<(), Box<dyn std::error::Error>> {
    Notification::new()
        .summary(title)
        .body(body)
        .icon("security-high")
        .timeout(5000)
        .show()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut current_status = get_current_status();
    let current_icon = get_icon(&current_status);
    let mut tray = TrayItem::new(
        "Agent Status",
        current_icon.resource(),
    )?;

    let label_id = tray.inner_mut().add_label_with_id("Agent Status")?;

    tray.inner_mut().add_separator()?;

    let (tx, rx) = mpsc::channel();

    let check_tx = tx.clone();
    tray.add_menu_item("Check Agents", move || {
        check_tx.send(Message::CheckAgents).unwrap();
    })?;

    tray.inner_mut().add_separator()?;

    let quit_tx = tx.clone();
    tray.add_menu_item("Quit", move || {
        quit_tx.send(Message::Quit).unwrap();
    })?;

    // Start a thread to check status every 5 seconds
    let update_tx = tx.clone();
    thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(5));
            update_tx.send(Message::UpdateStatus).unwrap();
        }
    });

    loop {
        match rx.recv() {
            Ok(Message::Quit) => {
                println!("Quit");
                break;
            }
            Ok(Message::CheckAgents) | Ok(Message::UpdateStatus) => {
                let new_status = get_current_status();
                let new_icon = get_icon(&new_status);
                tray.set_icon(new_icon.resource())?;
                
                let status_message = match new_icon {
                    Icon::NoAgents => "No agents installed or running",
                    Icon::OssecOnly => "OSSEC/Wazuh agent installed and running",
                    Icon::OsqueryOnly => "osquery installed and running",
                    Icon::BothAgents => "Both agents installed and running",
                };
                tray.inner_mut().set_label(status_message, label_id)?;

                // Check for status changes and send notifications
                if new_status != current_status {
                    if new_status.ossec_running != current_status.ossec_running {
                        let title = "OSSEC/Wazuh Agent Status Change";
                        let body = if new_status.ossec_running {
                            "OSSEC/Wazuh agent is now running"
                        } else {
                            "OSSEC/Wazuh agent is no longer running"
                        };
                        send_notification(title, body)?;
                    }
                    if new_status.osquery_running != current_status.osquery_running {
                        let title = "osquery Status Change";
                        let body = if new_status.osquery_running {
                            "osquery is now running"
                        } else {
                            "osquery is no longer running"
                        };
                        send_notification(title, body)?;
                    }
                    current_status = new_status;
                }
            },
            Err(_) => break,
        }
    }

    Ok(())
}