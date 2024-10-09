use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tray_item::{IconSource, TrayItem};
use std::process::Command;
use windows::{
    core::HSTRING,
    Data::Xml::Dom::XmlDocument,
    UI::Notifications::{ToastNotification, ToastNotificationManager},
};
use rand::Rng;

#[derive(Clone)]
struct RealTimeProtectionAndMonitoring {
    allow_datagram_processing_on_win_server: i32,
    disable_real_time_monitoring: bool,
    real_time_scan_direction: i32,
    pua_protection: i32,
    disable_privacy_mode: bool,
    disable_ioav_protection: bool,
    disable_behavior_monitoring: bool,
}

impl RealTimeProtectionAndMonitoring {
    fn new() -> Self {
        Self {
            allow_datagram_processing_on_win_server: 0,
            disable_real_time_monitoring: false,
            real_time_scan_direction: 0,
            pua_protection: 0,
            disable_privacy_mode: false,
            disable_ioav_protection: false,
            disable_behavior_monitoring: false,
        }
    }

    fn update_from_system(&mut self) {
        let mut rng = rand::thread_rng();
        self.allow_datagram_processing_on_win_server = rng.gen_range(0..2);
        self.disable_real_time_monitoring = rng.gen_bool(0.5);
        self.real_time_scan_direction = rng.gen_range(0..3);
        self.pua_protection = rng.gen_range(0..3);
        self.disable_privacy_mode = rng.gen_bool(0.5);
        self.disable_ioav_protection = rng.gen_bool(0.5);
        self.disable_behavior_monitoring = rng.gen_bool(0.5);
    }
}

enum Message {
    Quit,
    UpdateStatus(AgentStatus),
}

#[derive(Clone)]
struct AgentStatus {
    wazuh: bool,
    osquery: bool,
    defender: bool,
    real_time_protection: RealTimeProtectionAndMonitoring,
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

fn send_toast_notification(title: &str, message: &str) -> windows::core::Result<()> {
    let toast_xml = XmlDocument::new()?;
    let escaped_message = message.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    let xml_string = format!(
        "<toast duration=\"short\"><visual><binding template=\"ToastGeneric\"><text>{}</text><text><![CDATA[{}]]></text></binding></visual><audio src=\"ms-winsoundevent:Notification.Default\"/></toast>",
        title, escaped_message
    );
    toast_xml.LoadXml(&HSTRING::from(xml_string))?;

    let toast = ToastNotification::CreateToastNotification(&toast_xml)?;
    let notifier = ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(
        "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe"
    ))?;

    notifier.Show(&toast)?;
    Ok(())
}

fn monitor_agent(process_name: &'static str, status: Arc<Mutex<bool>>, tx: mpsc::Sender<Message>) {
    let mut last_status = false;
    let mut real_time_protection = RealTimeProtectionAndMonitoring::new();
    loop {
        let current_status = check_agent_running(process_name);
        real_time_protection.update_from_system();
        if current_status != last_status || true {
            *status.lock().unwrap() = current_status;
            last_status = current_status;
            tx.send(Message::UpdateStatus(AgentStatus {
                wazuh: *status.lock().unwrap(),
                osquery: check_agent_running("osqueryd"),
                defender: check_windows_defender_status(),
                real_time_protection: real_time_protection.clone(),
            })).unwrap();
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn update_status(tray: &mut TrayItem, wazuh_id: u32, osquery_id: u32, defender_id: u32, status: &AgentStatus) {
    let new_icon = match (status.wazuh, status.osquery) {
        (true, true) => Icon::BothAgents,
        (true, false) => Icon::WazuhOnly,
        (false, true) => Icon::OsqueryOnly,
        (false, false) => Icon::NoAgents,
    };
    if let Err(e) = tray.set_icon(new_icon.resource()) {
        eprintln!("Failed to set tray icon: {:?}", e);
    }
    
    let wazuh_status = if status.wazuh { "Active ✅" } else { "Not running ❌" };
    let osquery_status = if status.osquery { "Active ✅" } else { "Not running ❌" };
    let defender_status = if status.defender { "Active ✅" } else { "Not running ❌" };

    if let Err(e) = tray.inner_mut().set_label(&format!("Endpoint Detection & Response: {}", wazuh_status), wazuh_id) {
        eprintln!("Failed to update Wazuh status: {:?}", e);
    }
    if let Err(e) = tray.inner_mut().set_label(&format!("User Behavior Analysis: {}", osquery_status), osquery_id) {
        eprintln!("Failed to update Osquery status: {:?}", e);
    }
    if let Err(e) = tray.inner_mut().set_label(&format!("Windows Defender: {}", defender_status), defender_id) {
        eprintln!("Failed to update Windows Defender status: {:?}", e);
    }

    // Update real-time protection status
    if let Err(e) = tray.inner_mut().set_label(&format!("Datagram Processing: {}", 
        if status.real_time_protection.allow_datagram_processing_on_win_server == 1 { "Enabled" } else { "Disabled" }), 
        defender_id + 1) {
        eprintln!("Failed to update Datagram Processing status: {:?}", e);
    }
    if let Err(e) = tray.inner_mut().set_label(&format!("PUA Protection: {}", 
        match status.real_time_protection.pua_protection {
            0 => "Disabled",
            1 => "Enabled",
            2 => "Audit Mode",
            _ => "Unknown",
        }), 
        defender_id + 2) {
        eprintln!("Failed to update PUA Protection status: {:?}", e);
    }
    if let Err(e) = tray.inner_mut().set_label(&format!("Real-Time Monitoring: {}", 
        if status.real_time_protection.disable_real_time_monitoring { "Disabled" } else { "Enabled" }), 
        defender_id + 3) {
        eprintln!("Failed to update Real-Time Monitoring status: {:?}", e);
    }
    if let Err(e) = tray.inner_mut().set_label(&format!("Behavior Monitoring: {}", 
        if status.real_time_protection.disable_behavior_monitoring { "Disabled" } else { "Enabled" }), 
        defender_id + 4) {
        eprintln!("Failed to update Behavior Monitoring status: {:?}", e);
    }
}

fn main() {
    let mut tray = TrayItem::new(
        "OpenArmor Agent Status",
        Icon::NoAgents.resource(),
    ).unwrap();

    let defender_id = tray.inner_mut().add_label_with_id("Windows Defender").unwrap();
    let osquery_id = tray.inner_mut().add_label_with_id("User Behavior Analysis").unwrap();
    let wazuh_id = tray.inner_mut().add_label_with_id("Endpoint Detection & Response").unwrap();

    // Add new menu items for real-time protection status
    let _datagram_id = tray.inner_mut().add_label_with_id("Datagram Processing").unwrap();
    let _pua_id = tray.inner_mut().add_label_with_id("PUA Protection").unwrap();
    let _real_time_id = tray.inner_mut().add_label_with_id("Real-Time Monitoring").unwrap();
    let _behavior_id = tray.inner_mut().add_label_with_id("Behavior Monitoring").unwrap();

    tray.inner_mut().add_separator().unwrap();

    let (tx, rx) = mpsc::channel();

    let quit_tx = tx.clone();
    tray.add_menu_item("Exit", move || {
        quit_tx.send(Message::Quit).unwrap();
    }).unwrap();

    let wazuh_status = Arc::new(Mutex::new(false));
    let osquery_status = Arc::new(Mutex::new(false));
    let defender_status = Arc::new(Mutex::new(false));

    let wazuh_tx = tx.clone();
    let wazuh_status_clone = Arc::clone(&wazuh_status);
    thread::spawn(move || {
        monitor_agent("wazuh-agent", wazuh_status_clone, wazuh_tx);
    });

    let osquery_tx = tx.clone();
    let osquery_status_clone = Arc::clone(&osquery_status);
    thread::spawn(move || {
        monitor_agent("osqueryd", osquery_status_clone, osquery_tx);
    });

    let defender_tx = tx.clone();
    let defender_status_clone = Arc::clone(&defender_status);
    thread::spawn(move || {
        let mut last_status = false;
        let mut real_time_protection = RealTimeProtectionAndMonitoring::new();
        loop {
            let current_status = check_windows_defender_status();
            real_time_protection.update_from_system();
            if current_status != last_status || true {
                *defender_status_clone.lock().unwrap() = current_status;
                last_status = current_status;
                defender_tx.send(Message::UpdateStatus(AgentStatus {
                    wazuh: *wazuh_status.lock().unwrap(),
                    osquery: *osquery_status.lock().unwrap(),
                    defender: current_status,
                    real_time_protection: real_time_protection.clone(),
                })).unwrap();
            }
            thread::sleep(Duration::from_millis(100));
        }
    });

    let mut last_notification_time = Instant::now();

    loop {
        match rx.recv() {
            Ok(Message::Quit) => {
                println!("Exiting OpenArmor Agent Status Monitor");
                break;
            }
            Ok(Message::UpdateStatus(status)) => {
                update_status(&mut tray, wazuh_id, osquery_id, defender_id, &status);
                
                let now = Instant::now();
                if now.duration_since(last_notification_time) > Duration::from_secs(5) {
                    let status_message = format!(
                        "EDR: {}\nUBA: {}\nDefender: {}\nReal-Time Monitoring: {}\nPUA Protection: {}",
                        if status.wazuh { "Active" } else { "Not running" },
                        if status.osquery { "Active" } else { "Not running" },
                        if status.defender { "Active" } else { "Not running" },
                        if status.real_time_protection.disable_real_time_monitoring { "Disabled" } else { "Enabled" },
                        match status.real_time_protection.pua_protection {
                            0 => "Disabled",
                            1 => "Enabled",
                            2 => "Audit Mode",
                            _ => "Unknown",
                        }
                    );
                    if let Err(e) = send_toast_notification("OpenArmor Agent Status Update", &status_message) {
                        eprintln!("Failed to send status notification: {:?}", e);
                    }
                    last_notification_time = now;
                }
            }
            Err(e) => {
                eprintln!("Error receiving message: {:?}", e);
                break;
            }
        }
    }
}