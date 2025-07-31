# BTHome Scan CLI

[![CI](https://github.com/ducktec/bthome-monitor-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/ducktec/bthome-monitor-rs/actions/workflows/ci.yml)
[![Security Audit](https://github.com/ducktec/bthome-monitor-rs/actions/workflows/audit.yml/badge.svg)](https://github.com/ducktec/bthome-monitor-rs/actions/workflows/audit.yml)

A Rust CLI utility that scans for [BTHome](https://bthome.io/) Bluetooth Low Energy (BLE) advertisements and decodes their data. Both encrypted and unencrypted BTHome advertisements are supported.

## Installation

### Install via `cargo`

````bash
cargo install bthome-monitor-rs
````

### Building from Source

```bash
# Clone the repository
git clone https://github.com/ducktec/bthome-monitor-rs.git
cd bthome-monitor-rs

# Build with Cargo
cargo build --release

# Install the binary
cargo install --path .

# or alternatively
cargo run -- <options>
```

## Usage

```
CLI to scan BThome advertisement BLE packets

Usage: bthome-monitor-rs [OPTIONS]

Options:
  -v, --verbose            Enable verbose output
  -n, --name <NAME>        Only show devices with this name (optional)
  -r, --raw                Print raw advertisement data
  -t, --timeout <TIMEOUT>  Timeout in seconds (0 = run forever) [default: 0]
  -k, --key <KEY>          BTHome encryption key (32 hex characters for 16 bytes)
  -j, --json               Output data in JSON format
  -o, --output <OUTPUT>    Write output to a file instead of stdout
  -h, --help               Print help
  -V, --version            Print version
```

## Output Formats

### Human-Readable Text (Default)

```
Device: MySensor (D8:14:52:AB:CD:EF), RSSI: -67dBm
BTHome v2 | Not Encrypted
Data:
  temperature: 22.50 °C
  humidity: 45.50 %
  battery: 87 %
```

### JSON Format (`-j`)

```json
{
  "name": "MySensor",
  "address": "D8:14:52:AB:CD:EF",
  "rssi": -67,
  "data": {
    "version": 2,
    "is_trigger_based": false,
    "encryption_status": "NotEncrypted",
    "data": [
      {
        "measurement_type": "temperature",
        "value": 22.5,
        "unit": "°C"
      },
      {
        "measurement_type": "humidity",
        "value": 45.5,
        "unit": "%"
      },
      {
        "measurement_type": "battery",
        "value": 87,
        "unit": "%"
      }
    ]
  },
  "timestamp": "2025-07-29T12:34:56+00:00"
}
```

## Platform-Specific Notes

### macOS

Due to privacy restrictions in macOS, device addresses will be shown as device UUIDs instead of MAC addresses. This also means that decryption will not work on macOS, as the MAC address is part of the decryption process. See the [BTHome page](https://bthome.io/encryption/) on encryption for more details.

## Acknowledgments

- [BTHome project](https://bthome.io/) for the specification
- [btleplug](https://github.com/deviceplug/btleplug) for cross-platform Rust BLE support

## License

This library is licensed under either of
* MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)
* Apache License, Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
at your option.

## Contribution
Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.