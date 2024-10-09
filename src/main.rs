use std::sync::mpsc;
use tray_item::{IconSource, TrayItem};
use std::process::Command;

enum Message {
    Quit,
    CheckAgents,
    Hello,
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
    let ossec_installed = check_agent_installed("ossec-agent.exe") || check_agent_installed("wazuh-agent.exe");
    let osquery_installed = check_agent_installed("osqueryd.exe");

    // Additional check for running services
    let ossec_running = check_service_running("OssecSvc") || check_service_running("WazuhSvc");
    let osquery_running = check_service_running("osqueryd");

    match (ossec_installed && ossec_running, osquery_installed && osquery_running) {
        (true, true) => Icon::BothAgents,
        (true, false) => Icon::OssecOnly,
        (false, true) => Icon::OsqueryOnly,
        (false, false) => Icon::NoAgents,
    }
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

    // Add menu item for Hello action
    let hello_tx = tx.clone();
    tray.add_menu_item("Hello!", move || {
        hello_tx.send(Message::Hello).unwrap();
    })
    .unwrap();

    // Add menu item for checking agent status
    let check_tx = tx.clone();
    tray.add_menu_item("Check Agents", move || {
        check_tx.send(Message::CheckAgents).unwrap();
    })
    .unwrap();

    // Add menu items for OSSEC and osquery status (icons can be visualized based on tray, not directly on the menu item)
    tray.inner_mut().add_separator().unwrap();
    tray.add_menu_item("OSSEC Status", || {
        println!("Checking OSSEC status...");
    })
    .unwrap();
    tray.add_menu_item("osquery Status", || {
        println!("Checking osquery status...");
    })
    .unwrap();

    // Add Quit option
    tray.inner_mut().add_separator().unwrap();

    let quit_tx = tx.clone();
    tray.add_menu_item("Quit", move || {
        quit_tx.send(Message::Quit).unwrap();
    })
    .unwrap();

    // Main loop to handle tray menu events
    loop {
        match rx.recv() {
            Ok(Message::Quit) => {
                println!("Quit");
                break;
            }
            Ok(Message::CheckAgents) => {
                let new_icon = get_current_icon();
                tray.set_icon(new_icon.resource()).unwrap();
                
                let status_message = match new_icon {
                    Icon::NoAgents => "No agents installed or running",
                    Icon::OssecOnly => "OSSEC/Wazuh agent installed and running",
                    Icon::OsqueryOnly => "osquery installed and running",
                    Icon::BothAgents => "Both agents installed and running",
                };
                tray.inner_mut().set_label(status_message, label_id).unwrap();
            },
            Ok(Message::Hello) => {
                tray.inner_mut().set_label("Hi there!", label_id).unwrap();
            },
            _ => {}
        }
    }
}
