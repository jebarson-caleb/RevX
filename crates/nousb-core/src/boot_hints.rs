//! Read-only boot-environment hints: where the ESP is, which boot managers are present, and
//! what the firmware boot entries point at. Every field distinguishes "unknown" from "absent";
//! adapters fill in only what they can read without elevation or writes.

use super::{json_optional_value, json_string_array};

/// The UEFI global-variable GUID used by `Boot####`, `BootOrder`, `BootCurrent`, and `BootNext`.
pub const EFI_GLOBAL_VARIABLE_GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BootEnvironmentHints {
    pub esp_present: Option<bool>,
    pub esp_location: Option<String>,
    pub esp_size_bytes: Option<u64>,
    pub recovery_partition_present: Option<bool>,
    pub boot_managers: Vec<String>,
    pub firmware_boot_current: Option<String>,
    pub firmware_boot_order: Option<Vec<String>>,
    pub firmware_boot_next: Option<String>,
    pub network_boot_entries: Option<usize>,
    pub http_boot_entries: Option<usize>,
    pub unknowns: Vec<String>,
}

impl BootEnvironmentHints {
    pub fn to_json(&self) -> String {
        let optional_bool = |value: Option<bool>| {
            value
                .map(|value| value.to_string())
                .unwrap_or_else(|| "null".into())
        };
        let optional_count = |value: Option<usize>| {
            value
                .map(|value| value.to_string())
                .unwrap_or_else(|| "null".into())
        };
        format!(
            "{{\"esp_present\":{},\"esp_location\":{},\"esp_size_bytes\":{},\"recovery_partition_present\":{},\"boot_managers\":{},\"firmware_boot_current\":{},\"firmware_boot_order\":{},\"firmware_boot_next\":{},\"network_boot_entries\":{},\"http_boot_entries\":{},\"unknowns\":{}}}",
            optional_bool(self.esp_present),
            json_optional_value(self.esp_location.as_deref()),
            self.esp_size_bytes
                .map(|value| value.to_string())
                .unwrap_or_else(|| "null".into()),
            optional_bool(self.recovery_partition_present),
            json_string_array(&self.boot_managers),
            json_optional_value(self.firmware_boot_current.as_deref()),
            self.firmware_boot_order
                .as_ref()
                .map(|order| json_string_array(order))
                .unwrap_or_else(|| "null".into()),
            json_optional_value(self.firmware_boot_next.as_deref()),
            optional_count(self.network_boot_entries),
            optional_count(self.http_boot_entries),
            json_string_array(&self.unknowns),
        )
    }

    pub fn preview_lines(&self) -> Vec<String> {
        let tri = |value: Option<bool>| match value {
            Some(true) => "yes",
            Some(false) => "no",
            None => "unknown",
        };
        let count = |value: Option<usize>| {
            value
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".into())
        };
        let mut lines = vec![
            format!(
                "esp: {}{}",
                tri(self.esp_present),
                self.esp_location
                    .as_deref()
                    .map(|location| format!(" ({location})"))
                    .unwrap_or_default()
            ),
            format!(
                "recovery_partition: {}",
                tri(self.recovery_partition_present)
            ),
            format!(
                "boot_managers: {}",
                if self.boot_managers.is_empty() {
                    "unknown".to_string()
                } else {
                    self.boot_managers.join(", ")
                }
            ),
            format!(
                "firmware_boot_order: {}",
                self.firmware_boot_order
                    .as_ref()
                    .map(|order| order.join(","))
                    .unwrap_or_else(|| "unknown".into())
            ),
            format!(
                "firmware_boot_current: {}",
                self.firmware_boot_current.as_deref().unwrap_or("unknown")
            ),
            format!(
                "network_boot_entries: {} (http: {})",
                count(self.network_boot_entries),
                count(self.http_boot_entries)
            ),
        ];
        for unknown in &self.unknowns {
            lines.push(format!("unknown: {unknown}"));
        }
        lines
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EfiBootTarget {
    /// A partition (`HD()`) or file path on local media.
    LocalMedia,
    /// A whole device that firmware enumerated (for example `PciRoot()/Pci()`).
    Device,
    /// PXE-style network boot (MAC/IPv4/IPv6 without a URI).
    NetworkPxe,
    /// UEFI HTTP Boot (a URI node).
    NetworkHttp,
    /// An application inside the firmware volume (setup, boot menu, shell).
    FirmwareApplication,
    Unknown,
}

impl EfiBootTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            EfiBootTarget::LocalMedia => "local-media",
            EfiBootTarget::Device => "device",
            EfiBootTarget::NetworkPxe => "network-pxe",
            EfiBootTarget::NetworkHttp => "network-http",
            EfiBootTarget::FirmwareApplication => "firmware-application",
            EfiBootTarget::Unknown => "unknown",
        }
    }

    pub fn is_network(self) -> bool {
        matches!(self, EfiBootTarget::NetworkPxe | EfiBootTarget::NetworkHttp)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EfiLoadOption {
    pub active: bool,
    pub description: String,
    pub target: EfiBootTarget,
    pub file_path: Option<String>,
}

/// Parses an `EFI_LOAD_OPTION` (UEFI 2.11 section 3.1.3). `bytes` must not include the
/// four-byte attribute prefix that efivarfs adds.
pub fn parse_efi_load_option(bytes: &[u8]) -> Option<EfiLoadOption> {
    let attributes = u32::from_le_bytes(bytes.get(0..4)?.try_into().ok()?);
    let path_length = usize::from(u16::from_le_bytes(bytes.get(4..6)?.try_into().ok()?));
    let mut offset = 6;
    let mut description_units = Vec::new();
    loop {
        let unit = u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?);
        offset += 2;
        if unit == 0 {
            break;
        }
        description_units.push(unit);
    }
    let description = String::from_utf16_lossy(&description_units);
    let path = bytes.get(offset..offset + path_length)?;

    let mut target = EfiBootTarget::Unknown;
    let mut file_path = None;
    let mut saw_network = false;
    let mut saw_uri = false;
    let mut saw_media = false;
    let mut saw_firmware_volume = false;
    let mut saw_hardware = false;
    let mut node = 0;
    while node + 4 <= path.len() {
        let kind = path[node];
        let subtype = path[node + 1];
        let length = usize::from(u16::from_le_bytes([path[node + 2], path[node + 3]]));
        if length < 4 || node + length > path.len() {
            return None;
        }
        let data = &path[node + 4..node + length];
        match (kind, subtype) {
            (0x7f, 0xff) => break,
            (0x01, _) | (0x02, _) => saw_hardware = true,
            (0x03, 0x0b) | (0x03, 0x0c) | (0x03, 0x0d) => saw_network = true,
            (0x03, 0x18) => saw_uri = true,
            (0x04, 0x01) | (0x04, 0x02) => saw_media = true,
            (0x04, 0x04) => {
                saw_media = true;
                let units: Vec<u16> = data
                    .chunks_exact(2)
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .take_while(|unit| *unit != 0)
                    .collect();
                file_path = Some(String::from_utf16_lossy(&units));
            }
            (0x04, 0x06) | (0x04, 0x07) => saw_firmware_volume = true,
            _ => {}
        }
        node += length;
    }
    if saw_uri {
        target = EfiBootTarget::NetworkHttp;
    } else if saw_network {
        target = EfiBootTarget::NetworkPxe;
    } else if saw_firmware_volume {
        target = EfiBootTarget::FirmwareApplication;
    } else if saw_media {
        target = EfiBootTarget::LocalMedia;
    } else if saw_hardware {
        target = EfiBootTarget::Device;
    }
    Some(EfiLoadOption {
        active: attributes & 1 == 1,
        description,
        target,
        file_path,
    })
}

/// Parses a `BootOrder` value (little-endian UINT16 list) into `Boot####` identifiers.
pub fn parse_efi_boot_order(bytes: &[u8]) -> Vec<String> {
    bytes
        .chunks_exact(2)
        .map(|pair| format!("Boot{:04X}", u16::from_le_bytes([pair[0], pair[1]])))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        text.split_whitespace()
            .filter(|token| *token != "/")
            .map(|token| u8::from_str_radix(token, 16).unwrap())
            .collect()
    }

    fn load_option(description: &str, path: &[u8]) -> Vec<u8> {
        let mut bytes = 1u32.to_le_bytes().to_vec();
        bytes.extend((path.len() as u16).to_le_bytes());
        for unit in description.encode_utf16().chain([0]) {
            bytes.extend(unit.to_le_bytes());
        }
        bytes.extend(path);
        bytes
    }

    #[test]
    fn parses_entries_observed_in_the_disposable_ovmf_guest() {
        // Device paths printed by `efibootmgr -v` during the one-shot matrix.
        let one_shot = hex("04 01 2a 00 01 00 00 00 3f 00 00 00 00 00 00 00 c1 bf 0f 00 00 00 00 00 fa fd 1a be 00 00 00 00 00 00 00 00 00 00 00 00 01 01 / 04 04 30 00 5c 00 45 00 46 00 49 00 5c 00 42 00 4f 00 4f 00 54 00 5c 00 42 00 4f 00 4f 00 54 00 58 00 36 00 34 00 2e 00 45 00 46 00 49 00 00 00 / 7f ff 04 00");
        let option = parse_efi_load_option(&load_option("NoUSB-OneShot", &one_shot)).unwrap();
        assert!(option.active);
        assert_eq!(option.description, "NoUSB-OneShot");
        assert_eq!(option.target, EfiBootTarget::LocalMedia);
        assert_eq!(
            option.file_path.as_deref(),
            Some("\\EFI\\BOOT\\BOOTX64.EFI")
        );

        let device = hex("02 01 0c 00 d0 41 03 0a 00 00 00 00 / 01 01 06 00 00 05 / 7f ff 04 00");
        let option = parse_efi_load_option(&load_option("UEFI Misc Device", &device)).unwrap();
        assert_eq!(option.target, EfiBootTarget::Device);

        let setup = hex("04 07 14 00 c9 bd b8 7c eb f8 34 4f aa ea 3e e4 af 65 16 a1 / 04 06 14 00 21 aa 2c 46 14 76 03 45 83 6e 8a b6 f4 66 23 31 / 7f ff 04 00");
        let option = parse_efi_load_option(&load_option("EFI Firmware Setup", &setup)).unwrap();
        assert_eq!(option.target, EfiBootTarget::FirmwareApplication);
    }

    #[test]
    fn classifies_pxe_and_http_boot_entries() {
        let mut mac = vec![0x03, 0x0b, 0x25, 0x00];
        mac.extend([0u8; 0x21]);
        let mut ipv4 = vec![0x03, 0x0c, 0x1b, 0x00];
        ipv4.extend([0u8; 0x17]);
        let end = [0x7f, 0xff, 0x04, 0x00];
        let pxe = [mac.clone(), ipv4.clone(), end.to_vec()].concat();
        let option = parse_efi_load_option(&load_option("UEFI PXEv4", &pxe)).unwrap();
        assert_eq!(option.target, EfiBootTarget::NetworkPxe);
        assert!(option.target.is_network());

        let uri = [0x03, 0x18, 0x04, 0x00];
        let http = [mac, ipv4, uri.to_vec(), end.to_vec()].concat();
        let option = parse_efi_load_option(&load_option("UEFI HTTPv4", &http)).unwrap();
        assert_eq!(option.target, EfiBootTarget::NetworkHttp);
    }

    #[test]
    fn rejects_truncated_or_malformed_options_and_parses_boot_order() {
        assert!(parse_efi_load_option(&[1, 0, 0]).is_none());
        let broken = [0x04, 0x04, 0xff, 0x00];
        assert!(parse_efi_load_option(&load_option("x", &broken)).is_none());
        assert_eq!(
            parse_efi_boot_order(&[0x02, 0x00, 0x00, 0x00, 0x01, 0x00]),
            vec!["Boot0002", "Boot0000", "Boot0001"]
        );
    }

    #[test]
    fn hints_keep_unknown_distinct_from_absent() {
        let hints = BootEnvironmentHints {
            esp_present: Some(false),
            unknowns: vec!["firmware boot entries need elevation".into()],
            ..Default::default()
        };
        let json = hints.to_json();
        assert!(json.contains("\"esp_present\":false"));
        assert!(json.contains("\"network_boot_entries\":null"));
        assert!(hints
            .preview_lines()
            .iter()
            .any(|line| line == "network_boot_entries: unknown (http: unknown)"));
    }
}
