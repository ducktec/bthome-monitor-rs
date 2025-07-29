#![warn(unused_crate_dependencies)]
use anyhow::Result;
use btleplug::api::{Central, Manager as _, Peripheral as _, ScanFilter};
use btleplug::platform::Manager;
use clap::Parser;
use futures::stream::StreamExt;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

mod bthome;
use bthome::{BThomeData, BThomeValue, bthome_parser};

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
}

#[derive(Debug)]
struct Device {
    name: Option<String>,
    address: String,
    last_seen: Instant,
    data: Option<Vec<BThomeData>>,
    rssi: i16,
    raw_data: Option<Vec<u8>>,
    last_packet_id: Option<u64>,
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
        info!("Filtering for devices with name: {}", name);
    }

    // Indicate platform limitation on macOS
    if cfg!(target_os = "macos") {
        warn!(
            "On MacOS, device addresses will be shown as device UUIDs instead of MAC \
            addresses due to platform restrictions. \
            See https://developer.apple.com/documentation/corebluetooth/cbpeer/identifier"
        );
    }

    // Limit scanning to advertisements that contain BThome service data
    let scan_filter = ScanFilter {
        services: vec![BTHOME_UUID],
    };
    adapter.start_scan(scan_filter).await?;
    let mut event_stream = adapter.events().await?;

    while args.timeout == 0 || start_time.elapsed() < Duration::from_secs(args.timeout) {
        // Wait for the next event with a timeout to ensure graceful termination
        if let Ok(Some(event)) =
            tokio::time::timeout(Duration::from_millis(500), event_stream.next()).await
        {
            match event {
                btleplug::api::CentralEvent::ServiceDataAdvertisement { id, service_data } => {
                    if let Some(data) = service_data.get(&BTHOME_UUID) {
                        if let Ok(peripheral) = adapter.peripheral(&id).await {
                            if let Ok(properties) = peripheral.properties().await {
                                if let Some(properties) = properties {
                                    let local_name = properties.local_name.clone();
                                    let address = peripheral.id();
                                    let addr_str = format!("{}", address);

                                    if args.verbose {
                                        debug!(
                                            "Found BThome device: {} ({}), RSSI: {:?}",
                                            local_name.as_deref().unwrap_or("<unnamed>"),
                                            addr_str,
                                            properties.rssi
                                        );
                                    }

                                    process_advertisement(
                                        addr_str,
                                        local_name,
                                        properties.rssi,
                                        data.clone(),
                                        Arc::clone(&devices),
                                        &args,
                                    )
                                    .await?;
                                }
                            }
                        }
                    }
                }
                _ => {
                    // Ignore any other ble events
                }
            }
        }
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
    // Use address as device id (UUID on macOS, MAC address on others)
    // TODO: there seems to be an indication on macOS that the UUID may change
    let device_id = address.clone();

    // Filter by (local) name if specified
    if let Some(filter_name) = &args.name {
        if !local_name.as_deref().unwrap_or("").contains(filter_name) {
            return Ok(());
        }
    }

    let parsed_data = match bthome_parser(&data) {
        Ok(data) => {
            debug!("Successfully parsed BThome data");
            Some(data)
        }
        Err(e) => {
            warn!("Failed to parse BThome data: {}", e);
            None
        }
    };

    let mut devices_lock = devices.lock().await;

    // Update or insert device information into global tracking map
    let device = devices_lock.entry(device_id.clone()).or_insert(Device {
        name: None,
        address: address,
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
        device.raw_data = Some(data.clone());
    }

    if let Some(parsed) = &parsed_data {
        // Deduplicate printing advertisement data based on packet ID (if available)
        let mut current_packet_id = None;
        for item in parsed {
            if item.measurement_type == "packet_id" {
                if let BThomeValue::Uint(id) = &item.value {
                    current_packet_id = Some(*id);
                    break;
                }
            }
        }

        let should_print = match (current_packet_id, device.last_packet_id) {
            // If there's no packet ID in the data, always print
            (None, _) => true,

            // If we have a packet ID but no previous one, print
            (Some(_), None) => true,

            // If the packet ID has changed, print
            (Some(current), Some(last)) if current != last => true,

            // by default, don't print
            _ => false,
        };

        // Update the device data and last packet ID
        device.data = parsed_data;
        device.last_packet_id = current_packet_id;

        // Print if needed
        if should_print {
            print_device_info(device, args);
        }
    } else {
        // No parsed data - update device and print
        device.data = parsed_data;
        print_device_info(device, args);
    }

    Ok(())
}

fn print_device_info(device: &Device, args: &Args) {
    let name_display = device.name.as_deref().unwrap_or("<unnamed>");

    println!(
        "Device: {} ({}), RSSI: {}dBm",
        name_display, device.address, device.rssi
    );

    if let Some(data) = &device.data {
        if data.is_empty() {
            println!("  No BThome data found");
        } else {
            println!("  BThome data:");
            for item in data {
                println!("    {}: {}", item.measurement_type, item.value);
            }
        }
    }

    if args.raw {
        if let Some(raw) = &device.raw_data {
            println!("  Raw data: {}", hex::encode(raw));
        }
    }

    println!();
}
