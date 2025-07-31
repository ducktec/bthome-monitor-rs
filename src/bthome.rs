use aes::Aes128;
use anyhow::{Result, anyhow};
use ccm::{
    Ccm,
    aead::{Aead, KeyInit},
};
use generic_array::{
    GenericArray,
    typenum::{U4, U13},
};
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// BTHome service UUID
pub const BTHOME_UUID: Uuid = Uuid::from_u128(0x0000fcd200001000800000805f9b34fb);
/// Short BTHome service UUID (little-endian: D2FC)
pub const BTHOME_SHORT_UUID: &[u8; 2] = &[0xD2, 0xFC];

/// AES-CCM message authentication code length in bytes
const MIC_LENGTH: usize = 4;

/// BThome measurement data representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BThomeValue {
    Uint(u64),
    Int(i64),
    Float(f64),
    String(String),
    Bool(bool),
}

impl fmt::Display for BThomeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BThomeValue::Uint(v) => write!(f, "{v}"),
            BThomeValue::Int(v) => write!(f, "{v}"),
            BThomeValue::Float(v) => write!(f, "{v:.2}"),
            BThomeValue::String(v) => write!(f, "{v}"),
            BThomeValue::Bool(v) => write!(f, "{v}"),
        }
    }
}

/// A single BTHome data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BThomeData {
    pub measurement_type: String,
    pub value: BThomeValue,
    pub unit: String,
}

impl fmt::Display for BThomeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{measurement_type}: {value} {unit}",
            measurement_type = self.measurement_type,
            value = self.value,
            unit = self.unit
        )
    }
}

/// Encryption status
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EncryptionStatus {
    /// Not encrypted
    NotEncrypted,
    /// Encrypted but no key provided
    EncryptedNoKey,
    /// Encrypted but failed to decrypt
    EncryptedFailedDecryption(String),
    /// Successfully decrypted
    Decrypted,
}

impl fmt::Display for EncryptionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionStatus::NotEncrypted => write!(f, "Not Encrypted"),
            EncryptionStatus::EncryptedNoKey => write!(f, "Encrypted (No Key Provided)"),
            EncryptionStatus::EncryptedFailedDecryption(reason) => {
                write!(f, "Encrypted (Decryption Failed: {reason})")
            }
            EncryptionStatus::Decrypted => write!(f, "Decrypted"),
        }
    }
}

/// Container for BTHome advertisement data and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BThomePacket {
    /// The version of the BTHome protocol
    pub version: u8,
    /// Whether the device is trigger-based
    pub is_trigger_based: bool,
    /// The encryption status of the packet
    pub encryption_status: EncryptionStatus,
    /// Parse error, if any
    pub parse_error: Option<String>,
    /// The data points in the packet
    pub data: Vec<BThomeData>,
}

impl BThomePacket {
    /// Create regular BThomePacket
    pub fn new(
        version: u8,
        is_trigger_based: bool,
        encryption_status: EncryptionStatus,
        data: Vec<BThomeData>,
    ) -> Self {
        Self {
            version,
            is_trigger_based,
            encryption_status,
            parse_error: None,
            data,
        }
    }

    /// Create BThomePacket with a parse error
    pub fn with_error(
        version: u8,
        is_trigger_based: bool,
        encryption_status: EncryptionStatus,
        error: String,
    ) -> Self {
        Self {
            version,
            is_trigger_based,
            encryption_status,
            parse_error: Some(error),
            data: Vec::new(),
        }
    }
}

impl fmt::Display for BThomePacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "BTHome v{} | {}", self.version, self.encryption_status)?;

        if self.is_trigger_based {
            writeln!(f, "Trigger-based: Yes")?;
        }

        if let Some(ref error) = self.parse_error {
            writeln!(f, "Parse Error: {error}")?;
        }

        if !self.data.is_empty() {
            writeln!(f, "Data:")?;
            for data_point in &self.data {
                writeln!(f, "  {data_point}")?;
            }
        } else if self.parse_error.is_none() {
            writeln!(f, "No data points available")?;
        }

        Ok(())
    }
}

/// Parse raw BThome advertisement data into data points
pub fn bthome_parser(
    data: &[u8],
    encryption_key: Option<&str>,
    device_address: &str,
) -> Result<BThomePacket> {
    if data.is_empty() {
        return Err(anyhow!("Empty data"));
    }

    // Check BTHome protocol version (first byte, little-endian)
    let format_byte = data[0];

    // Extract encryption flag (bit 0)
    let is_encrypted = (format_byte & 0x01) != 0;

    // Extract trigger-based flag (bit 2)
    let is_trigger_based = (format_byte & 0x04) != 0;

    // Extract BTHome version (bits 5-7)
    let version = (format_byte >> 5) & 0x07;

    // Verify the BTHome version is supported
    if version != 2 {
        return Err(anyhow!(
            "Unsupported BTHome version: {version} (only version 2 supported)"
        ));
    }

    // Handle decryption if needed
    let (payload, encryption_status) = if is_encrypted {
        if let Some(key) = encryption_key {
            // Try to decrypt and return the payload
            match decrypt_bthome_data(data, key, device_address) {
                Ok(decrypted) => (decrypted, EncryptionStatus::Decrypted),
                Err(e) => {
                    warn!("Failed to decrypt BTHome data: {e}");
                    return Ok(BThomePacket::new(
                        version,
                        is_trigger_based,
                        EncryptionStatus::EncryptedFailedDecryption(e.to_string()),
                        Vec::new(),
                    ));
                }
            }
        } else {
            return Ok(BThomePacket::new(
                version,
                is_trigger_based,
                EncryptionStatus::EncryptedNoKey,
                Vec::new(),
            ));
        }
    } else {
        // Not encrypted, just skip the format byte
        (data[1..].to_vec(), EncryptionStatus::NotEncrypted)
    };

    // Parse the payload
    match parse_bthome_v2(&payload) {
        Ok(data_points) => Ok(BThomePacket::new(
            version,
            is_trigger_based,
            encryption_status,
            data_points,
        )),
        Err(e) => Ok(BThomePacket::with_error(
            version,
            is_trigger_based,
            encryption_status,
            e.to_string(),
        )),
    }
}

/// Parse entire BTHome v2 advertisement data into vector of data points
fn parse_bthome_v2(data: &[u8]) -> Result<Vec<BThomeData>> {
    let mut results = Vec::new();
    let mut i = 0;

    while i < data.len() {
        if i + 1 > data.len() {
            break; // End of adv data
        }

        let object_id = data[i];
        i += 1; // Already advance object ID past the object ID (data bytes will be advanced subsequently)

        // Try to parse the object
        match parse_bthome_object(object_id, data, &mut i) {
            Ok(data_point) => {
                debug!("Parsed BTHome data: {data_point}");
                results.push(data_point);
            }
            Err(e) => {
                // Parsing failed, stop processing
                return Err(e);
            }
        }
    }

    Ok(results)
}

/// Decrypt BTHome v2 encrypted data
fn decrypt_bthome_data(data: &[u8], encryption_key: &str, device_address: &str) -> Result<Vec<u8>> {
    // Format should be:
    // byte 0: BTHome device data byte (format byte)
    // bytes 1-N: Encrypted data
    // bytes N-(N+4): Counter (4 bytes)
    // bytes (N+4)-(N+8): MIC (4 bytes)

    if data.len() < 10 {
        // 1 (format) + 1 (min data) + 4 (counter) + 4 (MIC)
        return Err(anyhow!("Encrypted data is too short"));
    }

    // Check key format (length)
    let key_bytes = match hex::decode(encryption_key) {
        Ok(k) => k,
        Err(_) => {
            return Err(anyhow!(
                "Invalid encryption key format, must be 32 hex characters"
            ));
        }
    };

    if key_bytes.len() != 16 {
        return Err(anyhow!(
            "Invalid encryption key length, must be 16 bytes (32 hex characters)"
        ));
    }

    let mac_bytes = parse_mac_address(device_address)?;

    // Extract the format byte, counter, and MIC
    let format_byte = data[0];
    let counter_start = data.len() - MIC_LENGTH - 4;
    let counter = &data[counter_start..counter_start + 4];
    let mic = &data[counter_start + 4..];

    // The ciphertext is everything between the format byte and the counter
    let ciphertext = &data[1..counter_start];

    // Build the nonce: MAC(6) + UUID(2) + format(1) + counter(4)
    let mut nonce = Vec::with_capacity(13);
    nonce.extend_from_slice(&mac_bytes);
    nonce.extend_from_slice(BTHOME_SHORT_UUID);
    nonce.push(format_byte);
    nonce.extend_from_slice(counter);

    let key = GenericArray::clone_from_slice(&key_bytes);
    let nonce_array = GenericArray::clone_from_slice(&nonce);

    // Initialize the CCM cipher
    let cipher = Ccm::<Aes128, U4, U13>::new(&key);

    // Combine ciphertext and mic for decryption
    let mut combined = Vec::with_capacity(ciphertext.len() + mic.len());
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(mic);

    // Decrypt the data
    match cipher.decrypt(&nonce_array, combined.as_ref()) {
        Ok(plaintext) => {
            debug!(
                "Successfully decrypted BTHome data: {}",
                hex::encode(&plaintext)
            );
            Ok(plaintext)
        }
        Err(e) => Err(anyhow!("Decryption failed: {e}")),
    }
}

/// Parse a MAC address string into bytes
fn parse_mac_address(address: &str) -> Result<[u8; 6]> {
    let clean_address = address.replace(":", "").replace("-", "");

    // For macOS, the "address" will be a UUID, which we can't use for decryption, sorry :(
    if clean_address.len() != 12 {
        return Err(anyhow!("Invalid MAC address format for encryption"));
    }

    let mac_bytes = match hex::decode(&clean_address) {
        Ok(b) => {
            if b.len() != 6 {
                return Err(anyhow!("Invalid MAC address length"));
            }
            let mut result = [0u8; 6];
            result.copy_from_slice(&b);
            result
        }
        Err(_) => return Err(anyhow!("Invalid MAC address format")),
    };

    Ok(mac_bytes)
}

// Parse individual BTHome objects (we take the first matching one)
fn parse_bthome_object(object_id: u8, data: &[u8], i: &mut usize) -> Result<BThomeData> {
    if let Some(result) = parse_binary_sensor(object_id, data, i) {
        return Ok(result);
    }

    if let Some(result) = parse_event(object_id, data, i) {
        return Ok(result);
    }

    if let Some(result) = parse_device_info(object_id, data, i) {
        return Ok(result);
    }

    if let Some(result) = parse_sensor_data(object_id, data, i) {
        return Ok(result);
    }

    // No parser handled this object ID
    Err(anyhow!(
        "Unknown or unsupported object ID: {:#04x}",
        object_id
    ))
}

// Helper function to try to parse sensor type data
fn parse_sensor_data(object_id: u8, data: &[u8], i: &mut usize) -> Option<BThomeData> {
    match object_id {
        // Acceleration (uint16, 2 bytes, factor 0.001)
        0x51 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete acceleration data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.001;
            *i += 2;
            Some(BThomeData {
                measurement_type: "acceleration".to_string(),
                value: BThomeValue::Float(value),
                unit: "m/s²".to_string(),
            })
        }
        // Battery (uint8, 1 byte, factor 1)
        0x01 => {
            if *i + 1 > data.len() {
                log::warn!("Incomplete battery data");
                return None;
            }
            let raw = data[*i];
            *i += 1;
            Some(BThomeData {
                measurement_type: "battery".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "%".to_string(),
            })
        }
        // Channel (uint8, 1 byte, factor 1)
        0x60 => {
            if *i + 1 > data.len() {
                log::warn!("Incomplete channel data");
                return None;
            }
            let raw = data[*i];
            *i += 1;
            Some(BThomeData {
                measurement_type: "channel".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "".to_string(),
            })
        }
        // CO2 (uint16, 2 bytes, factor 1)
        0x12 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete CO2 data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            *i += 2;
            Some(BThomeData {
                measurement_type: "co2".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "ppm".to_string(),
            })
        }
        // Conductivity (uint16, 2 bytes, factor 1)
        0x56 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete conductivity data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            *i += 2;
            Some(BThomeData {
                measurement_type: "conductivity".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "µS/cm".to_string(),
            })
        }
        // Count (uint8, 1 byte, factor 1)
        0x09 => {
            if *i + 1 > data.len() {
                log::warn!("Incomplete count data");
                return None;
            }
            let raw = data[*i];
            *i += 1;
            Some(BThomeData {
                measurement_type: "count".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "".to_string(),
            })
        }
        // Count (uint16, 2 bytes, factor 1)
        0x3D => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete count data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            *i += 2;
            Some(BThomeData {
                measurement_type: "count".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "".to_string(),
            })
        }
        // Count (uint32, 4 bytes, factor 1)
        0x3E => {
            if *i + 4 > data.len() {
                log::warn!("Incomplete count data");
                return None;
            }
            let raw = u32::from_le_bytes([data[*i], data[*i + 1], data[*i + 2], data[*i + 3]]);
            *i += 4;
            Some(BThomeData {
                measurement_type: "count".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "".to_string(),
            })
        }
        // Count (sint8, 1 byte, factor 1)
        0x59 => {
            if *i + 1 > data.len() {
                log::warn!("Incomplete count data");
                return None;
            }
            let raw = data[*i] as i8;
            *i += 1;
            Some(BThomeData {
                measurement_type: "count".to_string(),
                value: BThomeValue::Int(raw as i64),
                unit: "".to_string(),
            })
        }
        // Count (sint16, 2 bytes, factor 1)
        0x5A => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete count data");
                return None;
            }
            let raw = i16::from_le_bytes([data[*i], data[*i + 1]]);
            *i += 2;
            Some(BThomeData {
                measurement_type: "count".to_string(),
                value: BThomeValue::Int(raw as i64),
                unit: "".to_string(),
            })
        }
        // Count (sint32, 4 bytes, factor 1)
        0x5B => {
            if *i + 4 > data.len() {
                log::warn!("Incomplete count data");
                return None;
            }
            let raw = i32::from_le_bytes([data[*i], data[*i + 1], data[*i + 2], data[*i + 3]]);
            *i += 4;
            Some(BThomeData {
                measurement_type: "count".to_string(),
                value: BThomeValue::Int(raw as i64),
                unit: "".to_string(),
            })
        }
        // Current (uint16, 2 bytes, factor 0.001)
        0x43 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete current data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.001;
            *i += 2;
            Some(BThomeData {
                measurement_type: "current".to_string(),
                value: BThomeValue::Float(value),
                unit: "A".to_string(),
            })
        }
        // Current (sint16, 2 bytes, factor 0.001)
        0x5D => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete current data");
                return None;
            }
            let raw = i16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.001;
            *i += 2;
            Some(BThomeData {
                measurement_type: "current".to_string(),
                value: BThomeValue::Float(value),
                unit: "A".to_string(),
            })
        }
        // Dewpoint (sint16, 2 bytes, factor 0.01)
        0x08 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete dewpoint data");
                return None;
            }
            let raw = i16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.01;
            *i += 2;
            Some(BThomeData {
                measurement_type: "dewpoint".to_string(),
                value: BThomeValue::Float(value),
                unit: "°C".to_string(),
            })
        }
        // Direction (uint16, 2 bytes, factor 0.01)
        0x5E => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete direction data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.01;
            *i += 2;
            Some(BThomeData {
                measurement_type: "direction".to_string(),
                value: BThomeValue::Float(value),
                unit: "°".to_string(),
            })
        }
        // Distance (mm, uint16, 2 bytes, factor 1)
        0x40 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete distance data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            *i += 2;
            Some(BThomeData {
                measurement_type: "distance_mm".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "mm".to_string(),
            })
        }
        // Distance (m, uint16, 2 bytes, factor 0.1)
        0x41 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete distance data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.1;
            *i += 2;
            Some(BThomeData {
                measurement_type: "distance_m".to_string(),
                value: BThomeValue::Float(value),
                unit: "m".to_string(),
            })
        }
        // Duration (uint24, 3 bytes, factor 0.001)
        0x42 => {
            if *i + 3 > data.len() {
                log::warn!("Incomplete duration data");
                return None;
            }
            let raw =
                ((data[*i + 2] as u32) << 16) | ((data[*i + 1] as u32) << 8) | (data[*i] as u32);
            let value = (raw as f64) * 0.001;
            *i += 3;
            Some(BThomeData {
                measurement_type: "duration".to_string(),
                value: BThomeValue::Float(value),
                unit: "s".to_string(),
            })
        }
        // Energy (uint32, 4 bytes, factor 0.001)
        0x4D => {
            if *i + 4 > data.len() {
                log::warn!("Incomplete energy data");
                return None;
            }
            let raw = u32::from_le_bytes([data[*i], data[*i + 1], data[*i + 2], data[*i + 3]]);
            let value = (raw as f64) * 0.001;
            *i += 4;
            Some(BThomeData {
                measurement_type: "energy".to_string(),
                value: BThomeValue::Float(value),
                unit: "Wh".to_string(),
            })
        }
        // Energy (uint24, 3 bytes, factor 0.001)
        0x0A => {
            if *i + 3 > data.len() {
                log::warn!("Incomplete energy data");
                return None;
            }
            let raw =
                ((data[*i + 2] as u32) << 16) | ((data[*i + 1] as u32) << 8) | (data[*i] as u32);
            let value = (raw as f64) * 0.001;
            *i += 3;
            Some(BThomeData {
                measurement_type: "energy".to_string(),
                value: BThomeValue::Float(value),
                unit: "kWh".to_string(),
            })
        }
        // Gas (uint24, 3 bytes, factor 1)
        0x4B => {
            if *i + 3 > data.len() {
                log::warn!("Incomplete gas data");
                return None;
            }
            let raw =
                ((data[*i + 2] as u32) << 16) | ((data[*i + 1] as u32) << 8) | (data[*i] as u32);
            *i += 3;
            Some(BThomeData {
                measurement_type: "gas".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "m3".to_string(),
            })
        }
        // Gas (uint32, 4 bytes, factor 1)
        0x4C => {
            if *i + 4 > data.len() {
                log::warn!("Incomplete gas data");
                return None;
            }
            let raw = u32::from_le_bytes([data[*i], data[*i + 1], data[*i + 2], data[*i + 3]]);
            *i += 4;
            Some(BThomeData {
                measurement_type: "gas".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "m3".to_string(),
            })
        }
        // Gyroscope (uint16, 2 bytes, factor 1)
        0x52 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete gyroscope data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            *i += 2;
            Some(BThomeData {
                measurement_type: "gyroscope".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "°/s".to_string(),
            })
        }
        // Humidity (uint16, 2 bytes, factor 0.01)
        0x03 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete humidity data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.01;
            *i += 2;
            Some(BThomeData {
                measurement_type: "humidity".to_string(),
                value: BThomeValue::Float(value),
                unit: "%".to_string(),
            })
        }
        // Humidity (uint8, 1 byte, factor 1)
        0x2E => {
            if *i + 1 > data.len() {
                log::warn!("Incomplete humidity data");
                return None;
            }
            let raw = data[*i];
            *i += 1;
            Some(BThomeData {
                measurement_type: "humidity".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "%".to_string(),
            })
        }
        // Illuminance (uint24, 3 bytes, factor 0.01)
        0x05 => {
            if *i + 3 > data.len() {
                log::warn!("Incomplete illuminance data");
                return None;
            }
            let raw =
                ((data[*i + 2] as u32) << 16) | ((data[*i + 1] as u32) << 8) | (data[*i] as u32);
            let value = (raw as f64) * 0.01;
            *i += 3;
            Some(BThomeData {
                measurement_type: "illuminance".to_string(),
                value: BThomeValue::Float(value),
                unit: "lux".to_string(),
            })
        }
        // Mass (kg, uint16, 2 bytes, factor 0.01)
        0x06 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete mass data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.01;
            *i += 2;
            Some(BThomeData {
                measurement_type: "mass_kg".to_string(),
                value: BThomeValue::Float(value),
                unit: "kg".to_string(),
            })
        }
        // Mass (lb, uint16, 2 bytes, factor 0.01)
        0x07 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete mass data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.01;
            *i += 2;
            Some(BThomeData {
                measurement_type: "mass_lb".to_string(),
                value: BThomeValue::Float(value),
                unit: "lb".to_string(),
            })
        }
        // Moisture (uint16, 2 bytes, factor 0.01)
        0x14 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete moisture data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.01;
            *i += 2;
            Some(BThomeData {
                measurement_type: "moisture".to_string(),
                value: BThomeValue::Float(value),
                unit: "%".to_string(),
            })
        }
        // Moisture (uint8, 1 byte, factor 1)
        0x2F => {
            if *i + 1 > data.len() {
                log::warn!("Incomplete moisture data");
                return None;
            }
            let raw = data[*i];
            *i += 1;
            Some(BThomeData {
                measurement_type: "moisture".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "%".to_string(),
            })
        }
        // PM2.5 (uint16, 2 bytes, factor 1)
        0x0D => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete PM2.5 data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            *i += 2;
            Some(BThomeData {
                measurement_type: "pm25".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "µg/m3".to_string(),
            })
        }
        // PM10 (uint16, 2 bytes, factor 1)
        0x0E => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete PM10 data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            *i += 2;
            Some(BThomeData {
                measurement_type: "pm10".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "µg/m3".to_string(),
            })
        }
        // Power (uint24, 3 bytes, factor 0.01)
        0x0B => {
            if *i + 3 > data.len() {
                log::warn!("Incomplete power data");
                return None;
            }
            let raw =
                ((data[*i + 2] as u32) << 16) | ((data[*i + 1] as u32) << 8) | (data[*i] as u32);
            let value = (raw as f64) * 0.01;
            *i += 3;
            Some(BThomeData {
                measurement_type: "power".to_string(),
                value: BThomeValue::Float(value),
                unit: "W".to_string(),
            })
        }
        // Power (sint32, 4 bytes, factor 0.01)
        0x5C => {
            if *i + 4 > data.len() {
                log::warn!("Incomplete power data");
                return None;
            }
            let raw = i32::from_le_bytes([data[*i], data[*i + 1], data[*i + 2], data[*i + 3]]);
            let value = (raw as f64) * 0.01;
            *i += 4;
            Some(BThomeData {
                measurement_type: "power".to_string(),
                value: BThomeValue::Float(value),
                unit: "W".to_string(),
            })
        }
        // Precipitation (uint16, 2 bytes, factor 0.1)
        0x5F => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete precipitation data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.1;
            *i += 2;
            Some(BThomeData {
                measurement_type: "precipitation".to_string(),
                value: BThomeValue::Float(value),
                unit: "mm".to_string(),
            })
        }
        // Pressure (uint24, 3 bytes, factor 0.01)
        0x04 => {
            if *i + 3 > data.len() {
                log::warn!("Incomplete pressure data");
                return None;
            }
            let raw =
                ((data[*i + 2] as u32) << 16) | ((data[*i + 1] as u32) << 8) | (data[*i] as u32);
            let value = (raw as f64) * 0.01;
            *i += 3;
            Some(BThomeData {
                measurement_type: "pressure".to_string(),
                value: BThomeValue::Float(value),
                unit: "hPa".to_string(),
            })
        }
        // Raw measurement data (variable length)
        0x54 => {
            if *i >= data.len() {
                log::warn!("Incomplete raw data");
                return None;
            }
            let len = data[*i] as usize;
            *i += 1;
            if *i + len > data.len() {
                log::warn!("Incomplete raw data");
                return None;
            }
            // Convert bytes to hex string
            let hex_string = data[*i..*i + len]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            *i += len;
            Some(BThomeData {
                measurement_type: "raw".to_string(),
                value: BThomeValue::String(hex_string),
                unit: "".to_string(),
            })
        }
        // Rotation (sint16, 2 bytes, factor 0.1)
        0x3F => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete rotation data");
                return None;
            }
            let raw = i16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.1;
            *i += 2;
            Some(BThomeData {
                measurement_type: "rotation".to_string(),
                value: BThomeValue::Float(value),
                unit: "°".to_string(),
            })
        }
        // Speed (uint16, 2 bytes, factor 0.01)
        0x44 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete speed data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.01;
            *i += 2;
            Some(BThomeData {
                measurement_type: "speed".to_string(),
                value: BThomeValue::Float(value),
                unit: "m/s".to_string(),
            })
        }
        // Temperature (sint8, 1 byte, factor 1)
        0x57 => {
            if *i + 1 > data.len() {
                log::warn!("Incomplete temperature data");
                return None;
            }
            let raw = data[*i] as i8;
            *i += 1;
            Some(BThomeData {
                measurement_type: "temperature".to_string(),
                value: BThomeValue::Int(raw as i64),
                unit: "°C".to_string(),
            })
        }
        // Temperature (sint8, 1 byte, factor 0.35)
        0x58 => {
            if *i + 1 > data.len() {
                log::warn!("Incomplete temperature data");
                return None;
            }
            let raw = data[*i] as i8;
            let value = (raw as f64) * 0.35;
            *i += 1;
            Some(BThomeData {
                measurement_type: "temperature".to_string(),
                value: BThomeValue::Float(value),
                unit: "°C".to_string(),
            })
        }
        // Temperature (sint16, 2 bytes, factor 0.1)
        0x45 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete temperature data");
                return None;
            }
            let raw = i16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.1;
            *i += 2;
            Some(BThomeData {
                measurement_type: "temperature".to_string(),
                value: BThomeValue::Float(value),
                unit: "°C".to_string(),
            })
        }
        // Temperature (sint16, 2 bytes, factor 0.01)
        0x02 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete temperature data");
                return None;
            }
            let raw = i16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.01;
            *i += 2;
            Some(BThomeData {
                measurement_type: "temperature".to_string(),
                value: BThomeValue::Float(value),
                unit: "°C".to_string(),
            })
        }
        // Text (variable length)
        0x53 => {
            if *i >= data.len() {
                log::warn!("Incomplete text data");
                return None;
            }
            let len = data[*i] as usize;
            *i += 1;
            if *i + len > data.len() {
                log::warn!("Incomplete text data");
                return None;
            }
            // Convert bytes to string
            match std::str::from_utf8(&data[*i..*i + len]) {
                Ok(text) => {
                    *i += len;
                    Some(BThomeData {
                        measurement_type: "text".to_string(),
                        value: BThomeValue::String(text.to_string()),
                        unit: "".to_string(),
                    })
                }
                Err(e) => {
                    log::warn!("Invalid UTF-8 in text data: {e}");
                    *i += len;
                    None
                }
            }
        }
        // Timestamp (uint32, 4 bytes)
        0x50 => {
            if *i + 4 > data.len() {
                log::warn!("Incomplete timestamp data");
                return None;
            }
            let raw = u32::from_le_bytes([data[*i], data[*i + 1], data[*i + 2], data[*i + 3]]);
            *i += 4;
            Some(BThomeData {
                measurement_type: "timestamp".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "s".to_string(),
            })
        }
        // TVOC (uint16, 2 bytes, factor 1)
        0x13 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete TVOC data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            *i += 2;
            Some(BThomeData {
                measurement_type: "tvoc".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "µg/m3".to_string(),
            })
        }
        // Voltage (uint16, 2 bytes, factor 1)
        0x0C => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete voltage data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.001;
            *i += 2;
            Some(BThomeData {
                measurement_type: "voltage".to_string(),
                value: BThomeValue::Float(value),
                unit: "V".to_string(),
            })
        }
        // Voltage (uint16, 2 bytes, factor 0.1)
        0x4A => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete voltage data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.1;
            *i += 2;
            Some(BThomeData {
                measurement_type: "voltage".to_string(),
                value: BThomeValue::Float(value),
                unit: "V".to_string(),
            })
        }
        // Volume (uint32, 4 bytes, factor 1)
        0x4E => {
            if *i + 4 > data.len() {
                log::warn!("Incomplete volume data");
                return None;
            }
            let raw = u32::from_le_bytes([data[*i], data[*i + 1], data[*i + 2], data[*i + 3]]);
            *i += 4;
            Some(BThomeData {
                measurement_type: "volume".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "L".to_string(),
            })
        }
        // Volume (uint16, 2 bytes, factor 0.1)
        0x47 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete volume data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.1;
            *i += 2;
            Some(BThomeData {
                measurement_type: "volume".to_string(),
                value: BThomeValue::Float(value),
                unit: "L".to_string(),
            })
        }
        // Volume (uint16, 2 bytes, factor 1)
        0x48 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete volume data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            *i += 2;
            Some(BThomeData {
                measurement_type: "volume".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "mL".to_string(),
            })
        }
        // Volume storage (uint32, 4 bytes, factor 1)
        0x55 => {
            if *i + 4 > data.len() {
                log::warn!("Incomplete volume storage data");
                return None;
            }
            let raw = u32::from_le_bytes([data[*i], data[*i + 1], data[*i + 2], data[*i + 3]]);
            *i += 4;
            Some(BThomeData {
                measurement_type: "volume_storage".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "L".to_string(),
            })
        }
        // Volume flow rate (uint16, 2 bytes, factor 1)
        0x49 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete volume flow rate data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            let value = (raw as f64) * 0.001;
            *i += 2;
            Some(BThomeData {
                measurement_type: "volume_flow_rate".to_string(),
                value: BThomeValue::Float(value),
                unit: "m3/hr".to_string(),
            })
        }
        // UV index (uint8, 1 byte, factor 0.1)
        0x46 => {
            if *i + 1 > data.len() {
                log::warn!("Incomplete UV index data");
                return None;
            }
            let raw = data[*i];
            let value = (raw as f64) * 0.1;
            *i += 1;
            Some(BThomeData {
                measurement_type: "uv_index".to_string(),
                value: BThomeValue::Float(value),
                unit: "".to_string(),
            })
        }
        // Water (uint32, 4 bytes, factor 1)
        0x4F => {
            if *i + 4 > data.len() {
                log::warn!("Incomplete water data");
                return None;
            }
            let raw = u32::from_le_bytes([data[*i], data[*i + 1], data[*i + 2], data[*i + 3]]);
            *i += 4;
            Some(BThomeData {
                measurement_type: "water".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "L".to_string(),
            })
        }
        _ => None,
    }
}

// Helper function to try to parse device information type data
fn parse_device_info(object_id: u8, data: &[u8], i: &mut usize) -> Option<BThomeData> {
    match object_id {
        // Packet ID (uint8, 1 byte, factor 1)
        0x00 => {
            if *i + 1 > data.len() {
                log::warn!("Incomplete packet ID data");
                return None;
            }
            let raw = data[*i];
            *i += 1;
            Some(BThomeData {
                measurement_type: "packet_id".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "".to_string(),
            })
        }
        // Device Type ID (uint16, 2 bytes, factor 1)
        0xF0 => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete device type ID data");
                return None;
            }
            let raw = u16::from_le_bytes([data[*i], data[*i + 1]]);
            *i += 2;
            Some(BThomeData {
                measurement_type: "device_type_id".to_string(),
                value: BThomeValue::Uint(raw as u64),
                unit: "".to_string(),
            })
        }
        // Firmware Version (uint32, 4 bytes) (major.minor.patch.build)
        0xF1 => {
            if *i + 4 > data.len() {
                log::warn!("Incomplete firmware version data");
                return None;
            }
            let raw = u32::from_le_bytes([data[*i], data[*i + 1], data[*i + 2], data[*i + 3]]);
            let build = raw & 0xFF;
            let patch = (raw >> 8) & 0xFF;
            let minor = (raw >> 16) & 0xFF;
            let major = (raw >> 24) & 0xFF;
            let version = format!("{major}.{minor}.{patch}.{build}");
            *i += 4;
            Some(BThomeData {
                measurement_type: "firmware_version".to_string(),
                value: BThomeValue::String(version),
                unit: "".to_string(),
            })
        }
        // Firmware Version (uint24, 3 bytes) (major.minor.patch)
        0xF2 => {
            if *i + 3 > data.len() {
                log::warn!("Incomplete firmware version data");
                return None;
            }
            let raw =
                ((data[*i + 2] as u32) << 16) | ((data[*i + 1] as u32) << 8) | (data[*i] as u32);
            let patch = raw & 0xFF;
            let minor = (raw >> 8) & 0xFF;
            let major = (raw >> 16) & 0xFF;
            let version = format!("{major}.{minor}.{patch}");
            *i += 3;
            Some(BThomeData {
                measurement_type: "firmware_version".to_string(),
                value: BThomeValue::String(version),
                unit: "".to_string(),
            })
        }
        _ => None,
    }
}

// Helper function to try to parse binary sensor data based on object ID
fn parse_binary_sensor(object_id: u8, data: &[u8], i: &mut usize) -> Option<BThomeData> {
    // Map of object IDs to measurement types for binary sensors
    let measurement_type = match object_id {
        0x0F => "generic_boolean",
        0x10 => "power",
        0x11 => "opening",
        0x15 => "battery_low",
        0x16 => "battery_charging",
        0x17 => "carbon_monoxide",
        0x18 => "cold",
        0x19 => "connectivity",
        0x1A => "door",
        0x1B => "garage_door",
        0x1C => "gas_detected",
        0x1D => "heat",
        0x1E => "light_detected",
        0x1F => "lock",
        0x20 => "moisture_detected",
        0x21 => "motion",
        0x22 => "moving",
        0x23 => "occupancy",
        0x24 => "plug",
        0x25 => "presence",
        0x26 => "problem",
        0x27 => "running",
        0x28 => "safety",
        0x29 => "smoke",
        0x2A => "sound",
        0x2B => "tamper",
        0x2C => "vibration",
        0x2D => "window",
        _ => return None,
    };

    if *i + 1 > data.len() {
        log::warn!("Incomplete binary sensor data for {measurement_type}");
        return None;
    }

    let raw = data[*i];
    *i += 1;
    Some(BThomeData {
        measurement_type: measurement_type.to_string(),
        value: BThomeValue::Bool(raw == 1),
        unit: "".to_string(),
    })
}

// Helper function to try to parse event data
fn parse_event(object_id: u8, data: &[u8], i: &mut usize) -> Option<BThomeData> {
    match object_id {
        // Button event
        0x3A => {
            if *i + 1 > data.len() {
                log::warn!("Incomplete button event data");
                return None;
            }
            let event_id = data[*i];
            *i += 1;
            let event_name = match event_id {
                0x00 => return None, // Don't add "none" events
                0x01 => "press".to_string(),
                0x02 => "double_press".to_string(),
                0x03 => "triple_press".to_string(),
                0x04 => "long_press".to_string(),
                0x05 => "long_double_press".to_string(),
                0x06 => "long_triple_press".to_string(),
                0x80 => "hold_press".to_string(),
                _ => {
                    log::warn!("Unknown button event ID: {:#04x}", event_id);
                    "unknown".to_string()
                }
            };

            Some(BThomeData {
                measurement_type: "button_event".to_string(),
                value: BThomeValue::String(event_name),
                unit: "".to_string(),
            })
        }
        // Dimmer event
        0x3B => {
            if *i + 2 > data.len() {
                log::warn!("Incomplete dimmer event data");
                return None;
            }
            let event_id = data[*i];
            let steps = data[*i + 1];
            *i += 2;

            let event_name = match event_id {
                0x00 => return None, // Don't add "none" events
                0x01 => format!("rotate_left_{steps}_steps"),
                0x02 => format!("rotate_right_{steps}_steps"),
                _ => {
                    log::warn!("Unknown dimmer event ID: {event_id:#04x}");
                    "unknown".to_string()
                }
            };

            Some(BThomeData {
                measurement_type: "dimmer_event".to_string(),
                value: BThomeValue::String(event_name),
                unit: "".to_string(),
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to create test data bytes
    fn create_test_data(is_encrypted: bool, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();

        // Format byte: Version 2 (bits 5-7 = 010), not trigger-based, encryption depends on parameter
        let format_byte = 0x40 | (if is_encrypted { 0x01 } else { 0x00 });
        result.push(format_byte);

        // Add the data
        result.extend_from_slice(data);

        result
    }

    // Helper function to check float values with an epsilon
    fn float_eq(a: f64, b: f64) -> bool {
        (a - b).abs() < 0.01
    }

    // Macro to create a test function for a sensor
    macro_rules! sensor_test {
        (
            $name:ident,                 // Test function name
            $object_id:expr,             // Object ID byte
            $data_bytes:expr,            // Raw data bytes
            $expected_type:expr,         // Expected measurement type
            $expected_value:expr,        // Expected value
            $expected_unit:expr          // Expected unit
        ) => {
            #[test]
            fn $name() {
                let mut test_data = vec![$object_id];
                test_data.extend_from_slice(&$data_bytes);

                let data = create_test_data(false, &test_data);
                let result = bthome_parser(&data, None, "00:00:00:00:00:00").unwrap();

                assert_eq!(result.version, 2, "Failed version check");
                assert_eq!(result.is_trigger_based, false, "Failed trigger-based check");
                assert_eq!(
                    result.encryption_status,
                    EncryptionStatus::NotEncrypted,
                    "Failed encryption status check"
                );
                assert_eq!(result.parse_error, None, "Failed parse error check");
                assert_eq!(result.data.len(), 1, "Failed data length check");

                let data_point = &result.data[0];
                assert_eq!(
                    data_point.measurement_type, $expected_type,
                    "Failed measurement type check"
                );
                assert_eq!(data_point.unit, $expected_unit, "Failed unit check");

                match (&data_point.value, &$expected_value) {
                    (BThomeValue::Uint(actual), BThomeValue::Uint(expected)) => {
                        assert_eq!(*actual, *expected, "Failed uint value check");
                    }
                    (BThomeValue::Int(actual), BThomeValue::Int(expected)) => {
                        assert_eq!(*actual, *expected, "Failed int value check");
                    }
                    (BThomeValue::Float(actual), BThomeValue::Float(expected)) => {
                        assert!(
                            float_eq(*actual, *expected),
                            "Failed float value check: got {actual}, expected {expected}"
                        );
                    }
                    (BThomeValue::String(actual), BThomeValue::String(expected)) => {
                        assert_eq!(actual, expected, "Failed string value check");
                    }
                    (BThomeValue::Bool(actual), BThomeValue::Bool(expected)) => {
                        assert_eq!(*actual, *expected, "Failed bool value check");
                    }
                    _ => {
                        panic!("Mismatched value types");
                    }
                }

                // Also check what happens if we have one byte too little
                let incomplete_data = create_test_data(false, &test_data[..test_data.len() - 1]);
                let incomplete_result =
                    bthome_parser(&incomplete_data, None, "00:00:00:00:00:00").unwrap();
                assert!(
                    incomplete_result.parse_error.is_some(),
                    "Expected a parse error for incomplete data"
                );
                assert_eq!(
                    incomplete_result.data.len(),
                    0,
                    "Expected no data points for incomplete data"
                );
            }
        };
    }

    // Macro to create a test function for error cases
    macro_rules! error_test {
        (
            $name:ident,                 // Test function name
            $object_id:expr,             // Object ID byte
            $data_bytes:expr             // Raw data bytes (incomplete)
        ) => {
            #[test]
            fn $name() {
                let mut test_data = vec![$object_id];
                test_data.extend_from_slice(&$data_bytes);

                let data = create_test_data(false, &test_data);
                let result = bthome_parser(&data, None, "00:00:00:00:00:00").unwrap();

                assert!(
                    result.parse_error.is_some(),
                    "Expected a parse error but none was found"
                );
                assert_eq!(result.data.len(), 0, "Expected no data points");
            }
        };
    }

    // Temperature tests
    sensor_test!(
        test_temperature_sint16_factor_001,
        0x02,             // Object ID
        vec![0xca, 0x09], // 2506 -> 25.06°C
        "temperature",
        BThomeValue::Float(25.06),
        "°C"
    );

    sensor_test!(
        test_temperature_sint16_factor_01,
        0x45,             // Object ID
        vec![0xF6, 0x00], // 246 -> 24.6°C
        "temperature",
        BThomeValue::Float(24.6),
        "°C"
    );

    sensor_test!(
        test_temperature_sint8_factor_1,
        0x57,       // Object ID
        vec![0x17], // 23°C
        "temperature",
        BThomeValue::Int(23),
        "°C"
    );

    // Humidity tests
    sensor_test!(
        test_humidity_uint16_factor_001,
        0x03,             // Object ID
        vec![0xbf, 0x13], // 5055 -> 50.55%
        "humidity",
        BThomeValue::Float(50.55),
        "%"
    );

    sensor_test!(
        test_humidity_uint8_factor_1,
        0x2E,       // Object ID
        vec![0x32], // 50%
        "humidity",
        BThomeValue::Uint(50),
        "%"
    );

    // Pressure test
    sensor_test!(
        test_pressure,
        0x04,                   // Object ID
        vec![0x13, 0x8a, 0x01], // 100883 -> 1008.83 hPa
        "pressure",
        BThomeValue::Float(1008.83),
        "hPa"
    );

    // Battery test
    sensor_test!(
        test_battery,
        0x01,       // Object ID
        vec![0x4e], // 78%
        "battery",
        BThomeValue::Uint(78),
        "%"
    );

    // Illuminance test
    sensor_test!(
        test_illuminance,
        0x05,                   // Object ID
        vec![0x39, 0x30, 0x00], // 12345 -> 123.45 lux
        "illuminance",
        BThomeValue::Float(123.45),
        "lux"
    );

    // Binary sensor tests
    sensor_test!(
        test_binary_sensor_power_on,
        0x10,       // Object ID
        vec![0x01], // On
        "power",
        BThomeValue::Bool(true),
        ""
    );

    sensor_test!(
        test_binary_sensor_door_closed,
        0x1A,       // Object ID
        vec![0x00], // Closed
        "door",
        BThomeValue::Bool(false),
        ""
    );

    // Tests for all the remaining sensor variants

    // Acceleration test
    sensor_test!(
        test_acceleration,
        0x51,             // Object ID
        vec![0xe8, 0x03], // 1000 -> 1.000 m/s²
        "acceleration",
        BThomeValue::Float(1.000),
        "m/s²"
    );

    // Channel test
    sensor_test!(
        test_channel,
        0x60,       // Object ID
        vec![0x0A], // 10
        "channel",
        BThomeValue::Uint(10),
        ""
    );

    // CO2 test
    sensor_test!(
        test_co2,
        0x12,             // Object ID
        vec![0x58, 0x02], // 600 ppm
        "co2",
        BThomeValue::Uint(600),
        "ppm"
    );

    // Conductivity test
    sensor_test!(
        test_conductivity,
        0x56,             // Object ID
        vec![0x96, 0x00], // 150 µS/cm
        "conductivity",
        BThomeValue::Uint(150),
        "µS/cm"
    );

    // Count tests
    sensor_test!(
        test_count_uint8,
        0x09,       // Object ID
        vec![0x05], // 5
        "count",
        BThomeValue::Uint(5),
        ""
    );

    sensor_test!(
        test_count_uint16,
        0x3D,             // Object ID
        vec![0xF4, 0x01], // 500
        "count",
        BThomeValue::Uint(500),
        ""
    );

    sensor_test!(
        test_count_uint32,
        0x3E,                         // Object ID
        vec![0x40, 0x42, 0x0F, 0x00], // 1000000
        "count",
        BThomeValue::Uint(1000000),
        ""
    );

    sensor_test!(
        test_count_sint8,
        0x59,       // Object ID
        vec![0xFB], // -5
        "count",
        BThomeValue::Int(-5),
        ""
    );

    sensor_test!(
        test_count_sint16,
        0x5A,             // Object ID
        vec![0x0C, 0xFE], // -500
        "count",
        BThomeValue::Int(-500),
        ""
    );

    sensor_test!(
        test_count_sint32,
        0x5B,                         // Object ID
        vec![0xC0, 0xBD, 0xF0, 0xFF], // -1000000
        "count",
        BThomeValue::Int(-1000000),
        ""
    );

    // Current tests
    sensor_test!(
        test_current_uint16,
        0x43,             // Object ID
        vec![0xE8, 0x03], // 1000 -> 1.000 A
        "current",
        BThomeValue::Float(1.000),
        "A"
    );

    sensor_test!(
        test_current_sint16,
        0x5D,             // Object ID
        vec![0x18, 0xFC], // -1000 -> -1.000 A
        "current",
        BThomeValue::Float(-1.000),
        "A"
    );

    // Dewpoint test
    sensor_test!(
        test_dewpoint,
        0x08,             // Object ID
        vec![0x94, 0x01], // 404 -> 4.04°C
        "dewpoint",
        BThomeValue::Float(4.04),
        "°C"
    );

    // Direction test
    sensor_test!(
        test_direction,
        0x5E,             // Object ID
        vec![0x68, 0x01], // 360 -> 3.60°
        "direction",
        BThomeValue::Float(3.60),
        "°"
    );

    // Distance tests
    sensor_test!(
        test_distance_mm,
        0x40,             // Object ID
        vec![0x14, 0x00], // 20 mm
        "distance_mm",
        BThomeValue::Uint(20),
        "mm"
    );

    sensor_test!(
        test_distance_m,
        0x41,             // Object ID
        vec![0x14, 0x00], // 20 -> 2.0 m
        "distance_m",
        BThomeValue::Float(2.0),
        "m"
    );

    // Duration test
    sensor_test!(
        test_duration,
        0x42,                   // Object ID
        vec![0xD0, 0x07, 0x00], // 2000 -> 2.000 s
        "duration",
        BThomeValue::Float(2.000),
        "s"
    );

    // Energy tests
    sensor_test!(
        test_energy_uint32,
        0x4D,                         // Object ID
        vec![0x10, 0x27, 0x00, 0x00], // 10000 -> 10.000 Wh
        "energy",
        BThomeValue::Float(10.000),
        "Wh"
    );

    sensor_test!(
        test_energy_uint24,
        0x0A,                   // Object ID
        vec![0x10, 0x27, 0x00], // 10000 -> 10.000 kWh
        "energy",
        BThomeValue::Float(10.000),
        "kWh"
    );

    // Gas tests
    sensor_test!(
        test_gas_uint24,
        0x4B,                   // Object ID
        vec![0x0A, 0x00, 0x00], // 10 m3
        "gas",
        BThomeValue::Uint(10),
        "m3"
    );

    sensor_test!(
        test_gas_uint32,
        0x4C,                         // Object ID
        vec![0x64, 0x00, 0x00, 0x00], // 100 m3
        "gas",
        BThomeValue::Uint(100),
        "m3"
    );

    // Gyroscope test
    sensor_test!(
        test_gyroscope,
        0x52,             // Object ID
        vec![0x2C, 0x01], // 300 °/s
        "gyroscope",
        BThomeValue::Uint(300),
        "°/s"
    );

    // Mass tests
    sensor_test!(
        test_mass_kg,
        0x06,             // Object ID
        vec![0x46, 0x00], // 70 -> 0.70 kg
        "mass_kg",
        BThomeValue::Float(0.70),
        "kg"
    );

    sensor_test!(
        test_mass_lb,
        0x07,             // Object ID
        vec![0x9D, 0x00], // 157 -> 1.57 lb
        "mass_lb",
        BThomeValue::Float(1.57),
        "lb"
    );

    // Moisture tests
    sensor_test!(
        test_moisture_uint16,
        0x14,             // Object ID
        vec![0xF4, 0x01], // 500 -> 5.00%
        "moisture",
        BThomeValue::Float(5.00),
        "%"
    );

    sensor_test!(
        test_moisture_uint8,
        0x2F,       // Object ID
        vec![0x05], // 5%
        "moisture",
        BThomeValue::Uint(5),
        "%"
    );

    // PM tests
    sensor_test!(
        test_pm25,
        0x0D,             // Object ID
        vec![0x14, 0x00], // 20 µg/m3
        "pm25",
        BThomeValue::Uint(20),
        "µg/m3"
    );

    sensor_test!(
        test_pm10,
        0x0E,             // Object ID
        vec![0x28, 0x00], // 40 µg/m3
        "pm10",
        BThomeValue::Uint(40),
        "µg/m3"
    );

    // Power tests
    sensor_test!(
        test_power_uint24,
        0x0B,                   // Object ID
        vec![0xE8, 0x03, 0x00], // 1000 -> 10.00 W
        "power",
        BThomeValue::Float(10.00),
        "W"
    );

    sensor_test!(
        test_power_sint32,
        0x5C,                         // Object ID
        vec![0x18, 0xFC, 0xFF, 0xFF], // -1000 -> -10.00 W
        "power",
        BThomeValue::Float(-10.00),
        "W"
    );

    // Precipitation test
    sensor_test!(
        test_precipitation,
        0x5F,             // Object ID
        vec![0x0A, 0x00], // 10 -> 1.0 mm
        "precipitation",
        BThomeValue::Float(1.0),
        "mm"
    );

    // Raw measurement test
    sensor_test!(
        test_raw_measurement,
        0x54,                         // Object ID
        vec![0x03, 0x01, 0x02, 0x03], // 3 bytes: 01 02 03
        "raw",
        BThomeValue::String("010203".to_string()),
        ""
    );

    // Rotation test
    sensor_test!(
        test_rotation,
        0x3F,             // Object ID
        vec![0x2C, 0x01], // 300 -> 30.0°
        "rotation",
        BThomeValue::Float(30.0),
        "°"
    );

    // Speed test
    sensor_test!(
        test_speed,
        0x44,             // Object ID
        vec![0x58, 0x02], // 600 -> 6.00 m/s
        "speed",
        BThomeValue::Float(6.00),
        "m/s"
    );

    // Temperature alternate representation tests
    sensor_test!(
        test_temperature_sint8_factor_035,
        0x58,       // Object ID
        vec![0x05], // 5 -> 1.75°C
        "temperature",
        BThomeValue::Float(1.75),
        "°C"
    );

    // Text test
    sensor_test!(
        test_text,
        0x53,                               // Object ID
        vec![0x04, 0x74, 0x65, 0x73, 0x74], // 4 bytes: "test"
        "text",
        BThomeValue::String("test".to_string()),
        ""
    );

    // Timestamp test
    sensor_test!(
        test_timestamp,
        0x50,                         // Object ID
        vec![0x00, 0x94, 0x35, 0x77], // 2000000000 s
        "timestamp",
        BThomeValue::Uint(2000000000),
        "s"
    );

    // TVOC test
    sensor_test!(
        test_tvoc,
        0x13,             // Object ID
        vec![0x32, 0x00], // 50 µg/m3
        "tvoc",
        BThomeValue::Uint(50),
        "µg/m3"
    );

    // Voltage tests
    sensor_test!(
        test_voltage_factor_0001,
        0x0C,             // Object ID
        vec![0xE8, 0x03], // 1000 -> 1.000 V
        "voltage",
        BThomeValue::Float(1.000),
        "V"
    );

    sensor_test!(
        test_voltage_factor_01,
        0x4A,             // Object ID
        vec![0x0A, 0x00], // 10 -> 1.0 V
        "voltage",
        BThomeValue::Float(1.0),
        "V"
    );

    // Volume tests
    sensor_test!(
        test_volume_uint32,
        0x4E,                         // Object ID
        vec![0x64, 0x00, 0x00, 0x00], // 100 L
        "volume",
        BThomeValue::Uint(100),
        "L"
    );

    sensor_test!(
        test_volume_uint16_factor_01,
        0x47,             // Object ID
        vec![0x64, 0x00], // 100 -> 10.0 L
        "volume",
        BThomeValue::Float(10.0),
        "L"
    );

    sensor_test!(
        test_volume_uint16_factor_1,
        0x48,             // Object ID
        vec![0x64, 0x00], // 100 mL
        "volume",
        BThomeValue::Uint(100),
        "mL"
    );

    // Volume storage test
    sensor_test!(
        test_volume_storage,
        0x55,                         // Object ID
        vec![0x10, 0x27, 0x00, 0x00], // 10000 L
        "volume_storage",
        BThomeValue::Uint(10000),
        "L"
    );

    // Volume flow rate test
    sensor_test!(
        test_volume_flow_rate,
        0x49,             // Object ID
        vec![0xE8, 0x03], // 1000 -> 1.000 m3/hr
        "volume_flow_rate",
        BThomeValue::Float(1.000),
        "m3/hr"
    );

    // UV index test
    sensor_test!(
        test_uv_index,
        0x46,       // Object ID
        vec![0x0A], // 10 -> 1.0
        "uv_index",
        BThomeValue::Float(1.0),
        ""
    );

    // Water test
    sensor_test!(
        test_water,
        0x4F,                         // Object ID
        vec![0x64, 0x00, 0x00, 0x00], // 100 L
        "water",
        BThomeValue::Uint(100),
        "L"
    );

    // Device Info tests
    sensor_test!(
        test_packet_id,
        0x00,       // Object ID
        vec![0x42], // 66
        "packet_id",
        BThomeValue::Uint(66),
        ""
    );

    sensor_test!(
        test_device_type_id,
        0xF0,             // Object ID
        vec![0x01, 0x00], // 1
        "device_type_id",
        BThomeValue::Uint(1),
        ""
    );

    // Test firmware version (major.minor.patch.build)
    sensor_test!(
        test_firmware_version_32bit,
        0xF1,                         // Object ID
        vec![0x04, 0x03, 0x02, 0x01], // 1.2.3.4
        "firmware_version",
        BThomeValue::String("1.2.3.4".to_string()),
        ""
    );

    // Test firmware version (major.minor.patch)
    sensor_test!(
        test_firmware_version_24bit,
        0xF2,                   // Object ID
        vec![0x03, 0x02, 0x01], // 1.2.3
        "firmware_version",
        BThomeValue::String("1.2.3".to_string()),
        ""
    );

    // Test for event button
    sensor_test!(
        test_event_button,
        0x3A,       // Object ID
        vec![0x01], // press
        "button_event",
        BThomeValue::String("press".to_string()),
        ""
    );

    sensor_test!(
        test_event_dimmer,
        0x3B,             // Object ID
        vec![0x01, 0x02], // rotate left 2 steps
        "dimmer_event",
        BThomeValue::String("rotate_left_2_steps".to_string()),
        ""
    );

    // Error test cases for incomplete data
    // Temperature missing one byte (should be 2 bytes)
    error_test!(
        test_temperature_sint16_incomplete,
        0x02,       // Object ID
        vec![0xca]  // Only 1 byte, needs 2
    );

    // Humidity missing one byte (should be 2 bytes)
    error_test!(
        test_humidity_uint16_incomplete,
        0x03,       // Object ID
        vec![0xbf]  // Only 1 byte, needs 2
    );

    // Pressure missing one byte (should be 3 bytes)
    error_test!(
        test_pressure_incomplete,
        0x04,             // Object ID
        vec![0x13, 0x8a]  // Only 2 bytes, needs 3
    );

    // Empty data
    error_test!(
        test_no_data,
        0x02,   // Object ID
        vec![]  // No data bytes
    );

    // CO2 missing one byte (should be 2 bytes)
    error_test!(
        test_co2_incomplete,
        0x12,       // Object ID
        vec![0xB8]  // Only 1 byte, needs 2
    );

    // Power incomplete (should be 3 bytes)
    error_test!(
        test_power_incomplete,
        0x0B,             // Object ID
        vec![0x10, 0x27]  // Only 2 bytes, needs 3
    );

    // Water incomplete (should be 4 bytes)
    error_test!(
        test_water_incomplete,
        0x4F,                   // Object ID
        vec![0x64, 0x00, 0x00]  // Only 3 bytes, needs 4
    );

    #[test]
    fn test_parse_multiple_data_points() {
        // Multiple data points: temperature, humidity, pressure
        let data = create_test_data(
            false,
            &[
                0x02, 0xca, 0x09, // Temperature 25.06°C
                0x03, 0xbf, 0x13, // Humidity 50.55%
                0x04, 0x13, 0x8a, 0x01, // Pressure 1008.83 hPa
            ],
        );

        let result = bthome_parser(&data, None, "00:00:00:00:00:00").unwrap();

        assert_eq!(None, result.parse_error);
        assert_eq!(result.data.len(), 3);

        let temp_data = &result.data[0];
        assert_eq!(temp_data.measurement_type, "temperature");
        assert!(matches!(temp_data.value, BThomeValue::Float(v) if (v - 25.06).abs() < 0.01));

        let humidity_data = &result.data[1];
        assert_eq!(humidity_data.measurement_type, "humidity");
        assert!(matches!(humidity_data.value, BThomeValue::Float(v) if (v - 50.55).abs() < 0.01));

        let pressure_data = &result.data[2];
        assert_eq!(pressure_data.measurement_type, "pressure");
        assert!(matches!(pressure_data.value, BThomeValue::Float(v) if (v - 1008.83).abs() < 0.01));
    }

    #[test]
    fn test_invalid_object_id() {
        // Invalid object ID 0xFE
        let data = create_test_data(false, &[0xFE, 0xca, 0x09]);

        let result = bthome_parser(&data, None, "00:00:00:00:00:00").unwrap();

        assert!(result.parse_error.is_some());
        assert_eq!(result.data.len(), 0);
    }

    #[test]
    fn test_unsupported_version() {
        // Unsupported version (3)
        let mut data = Vec::new();
        data.push(0x60); // Version 3 (bits 5-7 = 011)
        data.extend_from_slice(&[0x02, 0xca, 0x09]); // Temperature 25.06°C

        let result = bthome_parser(&data, None, "00:00:00:00:00:00");

        assert!(result.is_err());
    }

    #[test]
    fn test_trigger_based() {
        // Trigger-based data
        let mut data = Vec::new();
        data.push(0x44); // Version 2, trigger-based (bit 2 = 1)
        data.extend_from_slice(&[0x02, 0xca, 0x09]); // Temperature 25.06°C

        let result = bthome_parser(&data, None, "00:00:00:00:00:00").unwrap();

        assert_eq!(result.version, 2);
        assert_eq!(result.is_trigger_based, true);
    }

    // Test for parsing MAC address
    #[test]
    fn test_parse_mac_address() {
        let result = parse_mac_address("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(result, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

        let result = parse_mac_address("11:22:33:44:55:66").unwrap();
        assert_eq!(result, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

        let result = parse_mac_address("aa:bb:cc:dd:ee:ff");
        assert!(result.is_ok());

        let result = parse_mac_address("invalid");
        assert!(result.is_err());

        let result = parse_mac_address("AA:BB:CC:DD:EE");
        assert!(result.is_err());
    }

    #[test]
    fn test_bthome_value_display() {
        // Test unsigned integer display
        let uint_value = BThomeValue::Uint(42);
        assert_eq!(uint_value.to_string(), "42");

        // Test signed integer display
        let int_value = BThomeValue::Int(-23);
        assert_eq!(int_value.to_string(), "-23");

        // Test float display - should show 2 decimal places
        let float_value = BThomeValue::Float(25.06789);
        assert_eq!(float_value.to_string(), "25.07"); // Rounds to 2 decimal places

        // Test float display with exact 2 decimal places
        let float_value = BThomeValue::Float(10.50);
        assert_eq!(float_value.to_string(), "10.50");

        // Test string display
        let string_value = BThomeValue::String("test".to_string());
        assert_eq!(string_value.to_string(), "test");

        // Test boolean display
        let bool_true_value = BThomeValue::Bool(true);
        assert_eq!(bool_true_value.to_string(), "true");

        let bool_false_value = BThomeValue::Bool(false);
        assert_eq!(bool_false_value.to_string(), "false");
    }

    #[test]
    fn test_bthome_data_display() {
        // Test temperature data display
        let temp_data = BThomeData {
            measurement_type: "temperature".to_string(),
            value: BThomeValue::Float(25.06),
            unit: "°C".to_string(),
        };
        assert_eq!(temp_data.to_string(), "temperature: 25.06 °C");

        // Test humidity data display with integer value
        let humidity_data = BThomeData {
            measurement_type: "humidity".to_string(),
            value: BThomeValue::Uint(50),
            unit: "%".to_string(),
        };
        assert_eq!(humidity_data.to_string(), "humidity: 50 %");

        // Test binary sensor display
        let door_data = BThomeData {
            measurement_type: "door".to_string(),
            value: BThomeValue::Bool(false),
            unit: "".to_string(),
        };
        assert_eq!(door_data.to_string(), "door: false ");

        // Test event data display
        let event_data = BThomeData {
            measurement_type: "button_event".to_string(),
            value: BThomeValue::String("press".to_string()),
            unit: "".to_string(),
        };
        assert_eq!(event_data.to_string(), "button_event: press ");
    }

    #[test]
    fn test_encryption_status_display() {
        // Test not encrypted status
        let not_encrypted = EncryptionStatus::NotEncrypted;
        assert_eq!(not_encrypted.to_string(), "Not Encrypted");

        // Test encrypted but no key status
        let encrypted_no_key = EncryptionStatus::EncryptedNoKey;
        assert_eq!(encrypted_no_key.to_string(), "Encrypted (No Key Provided)");

        // Test encrypted but failed decryption status
        let failed_decryption =
            EncryptionStatus::EncryptedFailedDecryption("Invalid key".to_string());
        assert_eq!(
            failed_decryption.to_string(),
            "Encrypted (Decryption Failed: Invalid key)"
        );

        // Test successfully decrypted status
        let decrypted = EncryptionStatus::Decrypted;
        assert_eq!(decrypted.to_string(), "Decrypted");
    }

    #[test]
    fn test_bthome_packet_display() {
        // Create a packet with multiple data points
        let mut packet = BThomePacket::new(
            2,
            false,
            EncryptionStatus::NotEncrypted,
            vec![
                BThomeData {
                    measurement_type: "temperature".to_string(),
                    value: BThomeValue::Float(25.06),
                    unit: "°C".to_string(),
                },
                BThomeData {
                    measurement_type: "humidity".to_string(),
                    value: BThomeValue::Float(50.55),
                    unit: "%".to_string(),
                },
            ],
        );

        // Check the string representation
        let packet_string = packet.to_string();
        assert!(packet_string.contains("BTHome v2 | Not Encrypted"));
        assert!(packet_string.contains("temperature: 25.06 °C"));
        assert!(packet_string.contains("humidity: 50.55 %"));

        // Test with trigger-based
        packet.is_trigger_based = true;
        let packet_string = packet.to_string();
        assert!(packet_string.contains("Trigger-based: Yes"));

        // Test with parse error
        packet.parse_error = Some("Invalid data length".to_string());
        let packet_string = packet.to_string();
        assert!(packet_string.contains("Parse Error: Invalid data length"));

        // Test with error only
        let error_packet = BThomePacket::with_error(
            2,
            false,
            EncryptionStatus::EncryptedFailedDecryption("Bad key".to_string()),
            "Failed to parse data".to_string(),
        );

        let error_packet_string = format!("{error_packet}");
        assert!(error_packet_string.contains("BTHome v2 | Encrypted (Decryption Failed: Bad key)"));
        assert!(error_packet_string.contains("Parse Error: Failed to parse data"));
    }

    #[test]
    fn test_bindkey_wrong() {
        // Test BTHome parser with wrong encryption key
        // Based on povided spec example

        // Wrong encryption key
        let bindkey = "331d39c2d7cc1cd1aee224cd096db932";

        let data = vec![
            0x41, 0xa4, 0x72, 0x66, 0xc9, 0x5f, 0x73, 0x00, 0x11, 0x22, 0x33, 0x78, 0x23, 0x72,
            0x14,
        ];

        let address: &'static str = "54:48:E6:8F:80:A5";

        // Parse the data with the wrong key
        let result = bthome_parser(&data, Some(bindkey), address).unwrap();

        // Assert that the result indicates encryption with failed decryption
        assert_eq!(result.version, 2);
        assert_eq!(result.is_trigger_based, false);
        assert!(matches!(
            result.encryption_status,
            EncryptionStatus::EncryptedFailedDecryption(_)
        ));

        // Since decryption failed, there should be no data points
        assert_eq!(result.data.len(), 0);

        // The error should mention decryption failure
        match result.encryption_status {
            EncryptionStatus::EncryptedFailedDecryption(reason) => {
                assert!(
                    reason.contains("Decryption failed"),
                    "Expected decryption failure message"
                );
            }
            _ => panic!("Expected EncryptedFailedDecryption status"),
        }
    }

    #[test]
    fn test_bindkey_correct() {
        // Test BTHome parser with correct encryption key
        // Based on povided spec example

        // Correct encryption key
        let bindkey = "231d39c1d7cc1ab1aee224cd096db932";

        let data = vec![
            0x41, 0xa4, 0x72, 0x66, 0xc9, 0x5f, 0x73, 0x00, 0x11, 0x22, 0x33, 0x78, 0x23, 0x72,
            0x14,
        ];

        let address: &'static str = "54:48:E6:8F:80:A5";

        // Parse the data with the correct key
        let result = bthome_parser(&data, Some(bindkey), address).unwrap();

        // Assert that the result indicates successful decryption
        assert_eq!(result.version, 2);
        assert_eq!(result.is_trigger_based, false);
        assert_eq!(result.encryption_status, EncryptionStatus::Decrypted);

        // Verify there is no parse error
        assert_eq!(result.parse_error, None);

        // The data should contain temperature and humidity readings
        assert_eq!(result.data.len(), 2);

        // Verify temperature data point (25.06°C)
        let temp_data = &result.data[0];
        assert_eq!(temp_data.measurement_type, "temperature");
        assert!(matches!(temp_data.value, BThomeValue::Float(v) if (v - 25.06).abs() < 0.01));
        assert_eq!(temp_data.unit, "°C");

        // Verify humidity data point (50.55%)
        let humidity_data = &result.data[1];
        assert_eq!(humidity_data.measurement_type, "humidity");
        assert!(matches!(humidity_data.value, BThomeValue::Float(v) if (v - 50.55).abs() < 0.01));
        assert_eq!(humidity_data.unit, "%");
    }

    #[test]
    fn test_encryption_no_key() {
        // Test encrypted data when no key is provided

        // Data with encryption flag set
        let data = vec![
            0x41, 0xa4, 0x72, 0x66, 0xc9, 0x5f, 0x73, 0x00, 0x11, 0x22, 0x33, 0x78, 0x23, 0x72,
            0x14,
        ];

        let address = "54:48:E6:8F:80:A5";

        // Parse the data without providing a key
        let result = bthome_parser(&data, None, address).unwrap();

        // Assert that the result indicates encryption with no key
        assert_eq!(result.version, 2);
        assert_eq!(result.is_trigger_based, false);
        assert_eq!(result.encryption_status, EncryptionStatus::EncryptedNoKey);

        // Since no key was provided, there should be no data points
        assert_eq!(result.data.len(), 0);
    }

    #[test]
    fn test_encryption_invalid_key_format() {
        // Test encrypted data with an invalid key format

        // Invalid encryption key (not hex)
        let bindkey = "not-a-valid-hex-key";

        let data = vec![
            0x41, 0xa4, 0x72, 0x66, 0xc9, 0x5f, 0x73, 0x00, 0x11, 0x22, 0x33, 0x78, 0x23, 0x72,
            0x14,
        ];

        let address = "54:48:E6:8F:80:A5";

        // Parse the data with an invalid key
        let result = bthome_parser(&data, Some(bindkey), address).unwrap();

        // Assert that the result indicates encryption with failed decryption
        assert_eq!(result.version, 2);
        assert_eq!(result.is_trigger_based, false);
        assert!(matches!(
            result.encryption_status,
            EncryptionStatus::EncryptedFailedDecryption(_)
        ));

        // Since decryption failed, there should be no data points
        assert_eq!(result.data.len(), 0);

        // The error should mention invalid key format
        match result.encryption_status {
            EncryptionStatus::EncryptedFailedDecryption(reason) => {
                assert!(
                    reason.contains("Invalid encryption key format"),
                    "Expected invalid key format message"
                );
            }
            _ => panic!("Expected EncryptedFailedDecryption status"),
        }
    }

    #[test]
    fn test_encryption_key_wrong_length() {
        // Test encrypted data with a key of wrong length

        // Encryption key too short
        let bindkey = "814aac74c4f17b6c1581e1ab";

        let data = vec![
            0x41, 0xa4, 0x72, 0x66, 0xc9, 0x5f, 0x73, 0x00, 0x11, 0x22, 0x33, 0xb7, 0xce, 0xd8,
            0xe5,
        ];

        let address = "54:48:E6:8F:80:A5";

        // Parse the data with a key of wrong length
        let result = bthome_parser(&data, Some(bindkey), address).unwrap();

        // Assert that the result indicates encryption with failed decryption
        assert_eq!(result.version, 2);
        assert_eq!(result.is_trigger_based, false);
        assert!(matches!(
            result.encryption_status,
            EncryptionStatus::EncryptedFailedDecryption(_)
        ));

        // Since decryption failed, there should be no data points
        assert_eq!(result.data.len(), 0);

        // The error should mention invalid key length
        match result.encryption_status {
            EncryptionStatus::EncryptedFailedDecryption(reason) => {
                assert!(
                    reason.contains("Invalid encryption key length"),
                    "Expected invalid key length message"
                );
            }
            _ => panic!("Expected EncryptedFailedDecryption status"),
        }
    }

    #[test]
    fn test_encryption_invalid_mac() {
        // Test encrypted data with an invalid MAC address

        // Valid encryption key
        let bindkey = "231d39c1d7cc1ab1aee224cd096db932";

        let data = vec![
            0x41, 0xa4, 0x72, 0x66, 0xc9, 0x5f, 0x73, 0x00, 0x11, 0x22, 0x33, 0x78, 0x23, 0x72,
            0x14,
        ];

        // Invalid MAC address
        let address = "invalid-mac";

        // Parse the data with an invalid MAC
        let result = bthome_parser(&data, Some(bindkey), address).unwrap();

        // Assert that the result indicates encryption with failed decryption
        assert_eq!(result.version, 2);
        assert_eq!(result.is_trigger_based, false);
        assert!(matches!(
            result.encryption_status,
            EncryptionStatus::EncryptedFailedDecryption(_)
        ));

        // Since decryption failed, there should be no data points
        assert_eq!(result.data.len(), 0);

        // The error should mention invalid MAC address
        match result.encryption_status {
            EncryptionStatus::EncryptedFailedDecryption(reason) => {
                assert!(
                    reason.contains("Invalid MAC address"),
                    "Expected invalid MAC address message"
                );
            }
            _ => panic!("Expected EncryptedFailedDecryption status"),
        }
    }
}
