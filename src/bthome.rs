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
use std::fmt;
use uuid::Uuid;

/// BTHome service UUID
pub const BTHOME_UUID: Uuid = Uuid::from_u128(0x0000fcd200001000800000805f9b34fb);
/// Short BTHome service UUID (little-endian: D2FC)
pub const BTHOME_SHORT_UUID: &[u8; 2] = &[0xD2, 0xFC];

/// AES-CCM message authentication code length in bytes
const MIC_LENGTH: usize = 4;

/// BThome measurement data representation
#[derive(Debug, Clone)]
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
            BThomeValue::Uint(v) => write!(f, "{}", v),
            BThomeValue::Int(v) => write!(f, "{}", v),
            BThomeValue::Float(v) => write!(f, "{:.2}", v),
            BThomeValue::String(v) => write!(f, "{}", v),
            BThomeValue::Bool(v) => write!(f, "{}", v),
        }
    }
}

/// A single BTHome data point
#[derive(Debug, Clone)]
pub struct BThomeData {
    pub measurement_type: String,
    pub value: BThomeValue,
    pub unit: String,
}

impl fmt::Display for BThomeData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} {}", self.measurement_type, self.value, self.unit)
    }
}

/// Encryption status
#[derive(Debug, Clone, PartialEq)]
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
                write!(f, "Encrypted (Decryption Failed: {})", reason)
            }
            EncryptionStatus::Decrypted => write!(f, "Decrypted"),
        }
    }
}

/// Container for BTHome advertisement data and metadata
#[derive(Debug, Clone)]
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
            writeln!(f, "Parse Error: {}", error)?;
        }

        if !self.data.is_empty() {
            writeln!(f, "Data:")?;
            for data_point in &self.data {
                writeln!(f, "  {}", data_point)?;
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
            "Unsupported BTHome version: {} (only version 2 supported)",
            version
        ));
    }

    // Handle decryption if needed
    let (payload, encryption_status) = if is_encrypted {
        if let Some(key) = encryption_key {
            // Try to decrypt and return the payload
            match decrypt_bthome_data(data, key, device_address) {
                Ok(decrypted) => (decrypted, EncryptionStatus::Decrypted),
                Err(e) => {
                    warn!("Failed to decrypt BTHome data: {}", e);
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
                debug!("Parsed BTHome data: {}", data_point);
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
        Err(e) => Err(anyhow!("Decryption failed: {}", e)),
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
                .map(|b| format!("{:02x}", b))
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
                    log::warn!("Invalid UTF-8 in text data: {}", e);
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
            let version = format!("{}.{}.{}.{}", major, minor, patch, build);
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
            let version = format!("{}.{}.{}", major, minor, patch);
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
        log::warn!("Incomplete binary sensor data for {}", measurement_type);
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
                0x01 => format!("rotate_left_{}_steps", steps),
                0x02 => format!("rotate_right_{}_steps", steps),
                _ => {
                    log::warn!("Unknown dimmer event ID: {:#04x}", event_id);
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
