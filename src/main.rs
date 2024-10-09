use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use std::process::Command;
use tray_item::{IconSource, TrayItem};

enum Message {
    Quit,
    UpdateStatus,
}

enum Icon {
    NoAgents,
    WazuhOnly,
    OsqueryOnly,
    BothAgents,
}

impl Icon {
    fn resource(&self) -> IconSource {
        match self {
            Self::NoAgents => IconSource::Resource("icon-no-agents"),
            Self::WazuhOnly => IconSource::Resource("icon-wazuh-only"),
            Self::OsqueryOnly => IconSource::Resource("icon-osquery-only"),
            Self::BothAgents => IconSource::Resource("icon-both-agents"),
        }
    }
}

fn check_agent_installed(agent: &str) -> bool {
    let output = Command::new("cmd")
        .args(&["/C", "where", agent])
        .output()
        .expect("Failed to execute command");
    
    output.status.success()
}

fn check_service_running(service: &str) -> bool {
    let output = Command::new("sc")
        .args(&["query", service])
        .output()
        .expect("Failed to execute command");

    String::from_utf8_lossy(&output.stdout).contains("RUNNING")
}

fn get_current_icon() -> Icon {
    let wazuh_installed = check_agent_installed("wazuh-agent.exe");
    let osquery_installed = check_agent_installed("osqueryd.exe");

    // Check for running services
    let wazuh_running = check_service_running("WazuhSvc");
    let osquery_running = check_service_running("osqueryd");

    match (wazuh_installed && wazuh_running, osquery_installed && osquery_running) {
        (true, true) => Icon::BothAgents,
        (true, false) => Icon::WazuhOnly,
        (false, true) => Icon::OsqueryOnly,
        (false, false) => Icon::NoAgents,
    }
}

fn update_status(tray: &mut TrayItem, label_id: u32) {
    let new_icon = get_current_icon();
    tray.set_icon(new_icon.resource()).unwrap();
    
    let status_message = match new_icon {
        Icon::NoAgents => "No agents installed or running",
        Icon::WazuhOnly => "Wazuh agent installed and running",
        Icon::OsqueryOnly => "osquery installed and running",
        Icon::BothAgents => "Both agents installed and running",
    };
    tray.inner_mut().set_label(status_message, label_id).unwrap();
}

fn main() {
    // Initialize the tray icon based on the current agent status
    let current_icon = get_current_icon();
    let mut tray = TrayItem::new(
        "Agent Status",
        current_icon.resource(),
    )
    .unwrap();

    let label_id = tray.inner_mut().add_label_with_id("Agent Status").unwrap();

    tray.inner_mut().add_separator().unwrap();

    let (tx, rx) = mpsc::sync_channel(1);

    // Quit option
    let quit_tx = tx.clone();
    tray.add_menu_item("Quit", move || {
        quit_tx.send(Message::Quit).unwrap();
    })
    .unwrap();

    // Periodic status update in a separate thread
    let update_tx = tx.clone();
    thread::spawn(move || {
        loop {
            update_tx.send(Message::UpdateStatus).unwrap();
            thread::sleep(Duration::from_secs(5)); // Update every 5 seconds
        }
    });

    // Main event loop
    loop {
        match rx.recv() {
            Ok(Message::Quit) => {
                println!("Quit");
                break;
            }
            Ok(Message::UpdateStatus) => {
                update_status(&mut tray, label_id);
            }
            _ => {}
        }
    }
}
