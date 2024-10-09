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

fn get_current_icon() -> Icon {
    let wazuh_installed = check_agent_installed("C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe");
    let osquery_installed = check_agent_installed("C:\\Program Files\\osquery\\osqueryi.exe");

    let wazuh_running = check_agent_running("wazuh-agent");
    let osquery_running = check_agent_running("osqueryd");

    match (wazuh_installed && wazuh_running, osquery_installed && osquery_running) {
        (true, true) => Icon::BothAgents,
        (true, false) => Icon::WazuhOnly,
        (false, true) => Icon::OsqueryOnly,
        (false, false) => Icon::NoAgents,
    }
}

fn send_toast_notification(title: &str, message: &str) -> windows::core::Result<()> {
    let toast_xml = XmlDocument::new()?;
    let xml_string = format!(
        r#"<toast duration="short">
            <visual>
                <binding template="ToastGeneric">
                    <text>{}</text>
                    <text>{}</text>
                </binding>
            </visual>
            <audio src="ms-winsoundevent:Notification.Default" />
        </toast>"#,
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

    // Send a toast notification with sound
    if let Err(e) = send_toast_notification("Agent Status Update", status_message) {
        eprintln!("Failed to send toast notification: {:?}", e);
    }
}

fn main() {
    let current_icon = get_current_icon();
    let mut tray = TrayItem::new(
        "Agent Status",
        current_icon.resource(),
    )
    .unwrap();

    let label_id = tray.inner_mut().add_label_with_id("Agent Status").unwrap();

    tray.inner_mut().add_separator().unwrap();

    let (tx, rx) = mpsc::sync_channel(1);

    let quit_tx = tx.clone();
    tray.add_menu_item("Quit", move || {
        quit_tx.send(Message::Quit).unwrap();
    })
    .unwrap();

    let update_tx = tx.clone();
    thread::spawn(move || {
        loop {
            update_tx.send(Message::UpdateStatus).unwrap();
            thread::sleep(Duration::from_secs(5));
        }
    });

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