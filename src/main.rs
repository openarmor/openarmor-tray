use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tray_item::{IconSource, TrayItem};
use std::path::Path;
use std::process::Command;
use windows::{
    core::HSTRING,
    Data::Xml::Dom::XmlDocument,
    UI::Notifications::{ToastNotification, ToastNotificationManager},
};

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

fn check_agent_installed(agent_path: &str) -> bool {
    Path::new(agent_path).exists()
}

fn check_agent_running(process_name: &str) -> bool {
    let output = Command::new("powershell")
        .args(&["-Command", &format!("Get-Process {} -ErrorAction SilentlyContinue", process_name)])
        .output()
        .expect("Failed to execute PowerShell command");

    output.status.success() && !output.stdout.is_empty()
}

fn check_windows_defender_status() -> bool {
    let output = Command::new("powershell")
        .args(&["-Command", "Get-MpComputerStatus | Select-Object -ExpandProperty RealTimeProtectionEnabled"])
        .output()
        .expect("Failed to execute PowerShell command");

    String::from_utf8_lossy(&output.stdout).trim() == "True"
}

fn get_status_indicator(running: bool) -> &'static str {
    if running {
        "✅" 
    } else {
        "❌" 
    }
}

fn get_wazuh_status() -> String {
    let installed = check_agent_installed("C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe");
    let running = check_agent_running("wazuh-agent");
    let indicator = get_status_indicator(running);
    match (installed, running) {
        (true, true) => format!("Active {}", indicator),
        (true, false) => format!("Installed, not running {}", indicator),
        (false, _) => format!("Not installed {}", indicator),
    }
}

fn get_osquery_status() -> String {
    let installed = check_agent_installed("C:\\Program Files\\osquery\\osqueryi.exe");
    let running = check_agent_running("osqueryd");
    let indicator = get_status_indicator(running);
    match (installed, running) {
        (true, true) => format!("Active {}", indicator),
        (true, false) => format!("Installed, not running {}", indicator),
        (false, _) => format!("Not installed {}", indicator),
    }
}

fn get_windows_defender_status() -> String {
    let running = check_windows_defender_status();
    let indicator = get_status_indicator(running);
    if running {
        format!("Real-time protection active {}", indicator)
    } else {
        format!("Real-time protection inactive {}", indicator)
    }
}

fn get_current_icon() -> Icon {
    let wazuh_status = get_wazuh_status();
    let osquery_status = get_osquery_status();

    match (wazuh_status.contains("Active"), osquery_status.contains("Active")) {
        (true, true) => Icon::BothAgents,
        (true, false) => Icon::WazuhOnly,
        (false, true) => Icon::OsqueryOnly,
        (false, false) => Icon::NoAgents,
    }
}

fn send_toast_notification(title: &str, message: &str) -> windows::core::Result<()> {
    let toast_xml = XmlDocument::new()?;
    let xml_string = format!(
        "<toast duration=\"short\"><visual><binding template=\"ToastGeneric\"><text>{}</text><text>{}</text></binding></visual><audio src=\"ms-winsoundevent:Notification.Default\"/></toast>",
        title, message
    );
    toast_xml.LoadXml(&HSTRING::from(xml_string))?;

    let toast = ToastNotification::CreateToastNotification(&toast_xml)?;
    let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(
        "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe"
    ))?;

    notifier.Show(&toast)?;
    Ok(())
}

fn update_status(tray: &mut TrayItem, wazuh_id: u32, osquery_id: u32, defender_id: u32) {
    let new_icon = get_current_icon();
    if let Err(e) = tray.set_icon(new_icon.resource()) {
        eprintln!("Failed to set tray icon: {:?}", e);
    }
    
    let wazuh_status = get_wazuh_status();
    let osquery_status = get_osquery_status();
    let defender_status = get_windows_defender_status();

    if let Err(e) = tray.inner_mut().set_label(&format!("Endpoint Detection & Response: {}", wazuh_status), wazuh_id) {
        eprintln!("Failed to update Wazuh status: {:?}", e);
    }
    if let Err(e) = tray.inner_mut().set_label(&format!("User Behavior Analysis: {}", osquery_status), osquery_id) {
        eprintln!("Failed to update Osquery status: {:?}", e);
    }
    if let Err(e) = tray.inner_mut().set_label(&format!("Windows Defender: {}", defender_status), defender_id) {
        eprintln!("Failed to update Windows Defender status: {:?}", e);
    }

    let status_message = format!(
        "Endpoint Detection & Response: {}\nUser Behavior Analysis: {}\nWindows Defender: {}",
        wazuh_status, osquery_status, defender_status
    );
    if let Err(e) = send_toast_notification("Security Agent Status Update", &status_message) {
        eprintln!("Failed to send status notification: {:?}", e);
        eprintln!("Notification title: 'Security Agent Status Update'");
        eprintln!("Notification message: '{}'", status_message);
    }
}

fn main() {
    let current_icon = get_current_icon();
    let mut tray = TrayItem::new(
        "Security Agent Status",
        current_icon.resource(),
    )
    .unwrap();

    let defender_id = tray.inner_mut().add_label_with_id("Windows Defender").unwrap();
    let osquery_id = tray.inner_mut().add_label_with_id("User Behavior Analysis").unwrap();
    let wazuh_id = tray.inner_mut().add_label_with_id("Endpoint Detection & Response").unwrap();

    tray.inner_mut().add_separator().unwrap();

    let (tx, rx) = mpsc::sync_channel(1);

    let quit_tx = tx.clone();
    tray.add_menu_item("Exit", move || {
        quit_tx.send(Message::Quit).unwrap();
    })
    .unwrap();

    let update_tx = tx.clone();
    thread::spawn(move || {
        loop {
            update_tx.send(Message::UpdateStatus).unwrap();
            thread::sleep(Duration::from_secs(300)); // Update every 5 minutes
        }
    });

    loop {
        match rx.recv() {
            Ok(Message::Quit) => {
                println!("Exiting Security Agent Status Monitor");
                break;
            }
            Ok(Message::UpdateStatus) => {
                update_status(&mut tray, wazuh_id, osquery_id, defender_id);
            }
            _ => {}
        }
    }
}