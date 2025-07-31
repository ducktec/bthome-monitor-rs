#![warn(unused_crate_dependencies)]
use anyhow::Result;
use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::Manager;
use clap::Parser;
use futures::stream::StreamExt;
use log::{debug, info, warn};
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

mod bthome;
use bthome::{BThomePacket, BThomeValue, bthome_parser};

use crate::bthome::BTHOME_UUID;

/// CLI application to scan for BThome advertisement BLE packets
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Only show devices with this name (optional)
    #[arg(short, long)]
    name: Option<String>,

    /// Print raw advertisement data
    #[arg(short, long)]
    raw: bool,

    /// Timeout in seconds (0 = run forever)
    #[arg(short, long, default_value = "0")]
    timeout: u64,

    /// BTHome encryption key (32 hex characters for 16 bytes)
    #[arg(short, long)]
    key: Option<String>,

    /// Output data in JSON format
    #[arg(short = 'j', long)]
    json: bool,

    /// Write output to a file instead of stdout
    #[arg(short, long)]
    output: Option<String>,
}

#[derive(Debug)]
struct Device {
    name: Option<String>,
    address: String,
    last_seen: Instant,
    data: Option<BThomePacket>,
    rssi: i16,
    raw_data: Option<Vec<u8>>,
    last_packet_id: Option<u64>,
}

/// Serializable device data for JSON output
#[derive(Debug, Serialize)]
struct DeviceOutput<'a> {
    name: Option<&'a str>,
    address: &'a str,
    rssi: i16,
    data: &'a Option<BThomePacket>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_data: Option<String>,
    timestamp: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    if args.verbose {
        log::set_max_level(log::LevelFilter::Debug);
        debug!("Starting BThome monitor with args: {:?}", args);
    }

    let manager = Manager::new().await?;
    let adapters = manager.adapters().await?;
    if adapters.is_empty() {
        return Err("No Bluetooth adapters found".into());
    }

    let adapter = &adapters[0]; // Use the first adapter observed for now
    info!("Using Bluetooth adapter: {}", adapter.adapter_info().await?);

    let start_time = Instant::now();
    let devices = Arc::new(Mutex::new(HashMap::new()));

    info!("Starting BLE scan for BThome devices...");
    if let Some(name) = &args.name {
        info!("Filtering for devices with name: {name}");
    }

    if args.json {
        info!("Output format: JSON");
    } else {
        info!("Output format: Formatted to stdout");
    }

    if let Some(output_file) = &args.output {
        info!("Writing output to file: {output_file}");
    } else {
        info!("Writing output to stdout");
    }

    // Indicate platform limitation on macOS
    if cfg!(target_os = "macos") {
        warn!(
            "Device addresses will be shown as device UUIDs instead of MAC \
            addresses due to MacOS privacy restrictions."
        );
    }

    // Limit scanning to advertisements that contain BThome service data
    let scan_filter = ScanFilter {
        services: vec![BTHOME_UUID],
    };
    adapter.start_scan(scan_filter).await?;
    let mut event_stream = adapter.events().await?;

    if let Some(output_file) = &args.output
        && let Err(e) = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(output_file)
    {
        return Err(format!("Failed to create output file {output_file}: {e}").into());
    }

    while args.timeout == 0 || start_time.elapsed() < Duration::from_secs(args.timeout) {
        // Wait for the next event with a timeout to ensure graceful termination
        let event =
            match tokio::time::timeout(Duration::from_millis(500), event_stream.next()).await {
                Ok(Some(event)) => event,
                _ => continue,
            };

        // Only process service data advertisements with BTHome data
        let (id, data) = match event {
            btleplug::api::CentralEvent::ServiceDataAdvertisement { id, service_data } => {
                match service_data.get(&BTHOME_UUID) {
                    Some(data) => (id, data.clone()),
                    None => continue,
                }
            }
            _ => continue, // Ignore any other BLE events
        };

        let peripheral = match adapter.peripheral(&id).await {
            Ok(p) => p,
            Err(_) => continue,
        };

        let properties = match peripheral.properties().await {
            Ok(Some(props)) => props,
            _ => continue,
        };

        let local_name = properties.local_name.clone();
        let address = peripheral.id();
        let addr_str = address.to_string();

        if args.verbose {
            debug!(
                "Found BThome device: {} ({}), RSSI: {rssi:?}",
                local_name.as_deref().unwrap_or("<unnamed>"),
                addr_str,
                rssi = properties.rssi
            );
        }

        process_advertisement(
            addr_str,
            local_name,
            properties.rssi,
            data,
            Arc::clone(&devices),
            &args,
        )
        .await?;
    }

    info!("Stopping scan");
    adapter.stop_scan().await?;

    Ok(())
}

async fn process_advertisement(
    address: String,
    local_name: Option<String>,
    rssi: Option<i16>,
    data: Vec<u8>,
    devices: Arc<Mutex<HashMap<String, Device>>>,
    args: &Args,
) -> Result<()> {
    // Filter by name if specified
    if let Some(filter_name) = &args.name
        && !local_name.as_deref().unwrap_or("").contains(filter_name)
    {
        return Ok(());
    }

    let parsed_data = match bthome_parser(&data, args.key.as_deref(), &address) {
        Ok(packet) => {
            debug!("Successfully parsed BThome data");
            Some(packet)
        }
        Err(e) => {
            warn!("Failed to parse BThome data: {e}");
            None
        }
    };

    let mut devices_lock = devices.lock().await;
    let device = devices_lock.entry(address.clone()).or_insert(Device {
        name: None,
        address,
        last_seen: Instant::now(),
        data: None,
        rssi: rssi.unwrap_or(-127),
        raw_data: None,
        last_packet_id: None,
    });

    device.name = local_name;
    device.last_seen = Instant::now();
    device.rssi = rssi.unwrap_or(-127);
    if args.raw {
        device.raw_data = Some(data);
    }

    let current_packet_id = parsed_data.as_ref().and_then(|packet| {
        packet
            .data
            .iter()
            .find(|item| item.measurement_type == "packet_id")
            .and_then(|item| {
                if let BThomeValue::Uint(id) = &item.value {
                    Some(*id)
                } else {
                    None
                }
            })
    });

    // Determine if we should print based on (past and current) packet ID
    let should_print = match (current_packet_id, device.last_packet_id) {
        (None, _) => true,       // No packet ID, always print
        (Some(_), None) => true, // First packet with ID, print
        (Some(current), Some(last)) if current != last => true, // ID changed, print
        _ => parsed_data.is_none(), // For unchanged IDs, only print if there was an error
    };

    // Update device data for future checks
    device.data = parsed_data;
    device.last_packet_id = current_packet_id;

    if should_print {
        print_device_info(device, args);
    }

    Ok(())
}

fn print_device_info(device: &Device, args: &Args) {
    let timestamp = chrono::Local::now().to_rfc3339();

    if args.json {
        let raw_data_hex = device.raw_data.as_ref().map(hex::encode);
        let output = DeviceOutput {
            name: device.name.as_deref(),
            address: &device.address,
            rssi: device.rssi,
            data: &device.data,
            raw_data: raw_data_hex,
            timestamp,
        };

        let json_string = serde_json::to_string(&output).unwrap_or_else(|e| {
            warn!("Failed to serialize to JSON: {e}");
            "{}".to_string()
        });

        if let Some(output_file) = &args.output {
            write_to_file(output_file, &json_string).unwrap_or_else(|e| {
                warn!("Failed to write to file {output_file}: {e}");
            });
        } else {
            println!("{json_string}");
        }
    } else {
        // Traditional text output
        let name_display = device.name.as_deref().unwrap_or("<unnamed>");

        // Header
        println!(
            "Device: {} ({}), RSSI: {}dBm",
            name_display, device.address, device.rssi
        );

        // Parsed data
        match &device.data {
            Some(packet) => println!("{packet}"),
            None => println!("  No BThome data found"),
        }

        // Raw data (only if requested)
        if args.raw
            && let Some(raw) = &device.raw_data
        {
            println!("  Raw data: {}", hex::encode(raw));
        }

        println!();
    }
}

// Helper function to write data to a file
fn write_to_file(path: &str, data: &str) -> Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;

    writeln!(file, "{data}")?;
    Ok(())
}
