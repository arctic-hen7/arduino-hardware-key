use crate::error::HardwareKeyError;
use serialport::SerialPort;
use std::{
    io::{BufRead, BufReader},
    time::Duration,
};

/// The identifier we expect the hardware key to send when we ask it to identify itself.
const IDENTIFIER: &str = "arduino_hardware_key";
/// The number of milliseconds to allow for I/O timeouts. This will be board-dependent.
const TIMEOUT_MS: u64 = 300;

/// A hardware key capable of performing challenge-response authentication.
// TODO: Set up a backing hardware resource so we can clone to have multiple slots on the one
// device. Handling this with concurrency could be tricky...
pub struct HardwareKey {
    /// The port itself, to write to.
    port: Box<dyn SerialPort>,
    /// A buffer reader wrapper over the port, to read from it line-by-line.
    port_reader: BufReader<Box<dyn SerialPort>>,
    /// The slot to use for operations.
    slot: u8,
}
impl HardwareKey {
    /// Sets up a new hardware key at the given port, connecting to the given key slot.
    ///
    /// This will initialise the connection and ask the device to identify itself, failing if it
    /// doesn't appear to speak the expected protocol.
    pub fn new(port: &str, baud_rate: u32, slot: u8) -> Result<Self, HardwareKeyError> {
        let mut port = serialport::new(port, baud_rate)
            .timeout(Duration::from_millis(TIMEOUT_MS))
            .open()
            .map_err(|source| HardwareKeyError::PortOpenFailed {
                port: port.to_string(),
                source,
            })?;
        let mut port_reader = BufReader::new(
            port.try_clone()
                .map_err(HardwareKeyError::PortCloneFailed)?,
        );

        // Get the key to identify itself
        let mut buf = String::new();
        port.write_all(b"identify\n")
            .map_err(HardwareKeyError::WriteFailed)?;
        port_reader
            .read_line(&mut buf)
            .map_err(HardwareKeyError::ReadFailed)?;
        if buf.trim() != IDENTIFIER {
            return Err(HardwareKeyError::BadIdentifier {
                id: buf.trim().to_string(),
            });
        }

        Ok(Self {
            port,
            port_reader,
            slot,
        })
    }
    /// Tells the hardware key to generate a new key in the given slot. This will override any
    /// existing keys in that slot!
    pub fn generate_key(&mut self) -> Result<(), HardwareKeyError> {
        self.port
            .write_all(&format!("generate {}\n", self.slot).into_bytes())
            .map_err(HardwareKeyError::WriteFailed)?;

        let mut buf = String::new();
        self.port_reader
            .read_line(&mut buf)
            .map_err(HardwareKeyError::ReadFailed)?;
        if buf.trim().starts_with("success: ") {
            Ok(())
        } else {
            let error = buf.trim().split(": ").nth(1).unwrap().trim();

            match error {
                "invalid slot number" => Err(HardwareKeyError::InvalidSlot(self.slot)),
                _ => Err(HardwareKeyError::UnknownError(error.to_string())),
            }
        }
    }
    /// Sends the given data to the hardware key using the key in the given slot, requesting it to
    /// generate an HMAC response, which will, if successful, be a hexadecimal string.
    pub fn challenge(&mut self, data: &str) -> Result<String, HardwareKeyError> {
        self.port
            .write_all(&format!("challenge {} {}\n", self.slot, data).into_bytes())
            .map_err(HardwareKeyError::WriteFailed)?;

        let mut buf = String::new();
        self.port_reader
            .read_line(&mut buf)
            .map_err(HardwareKeyError::ReadFailed)?;
        if buf.trim().starts_with("success: ") {
            Ok(buf.trim().split(": ").nth(1).unwrap().to_string())
        } else {
            let error = buf.trim().split(": ").nth(1).unwrap().trim();

            match error {
                "invalid slot number" => Err(HardwareKeyError::InvalidSlot(self.slot)),
                "no key in slot" => Err(HardwareKeyError::NoKeyInSlot(self.slot)),
                _ => Err(HardwareKeyError::UnknownError(error.to_string())),
            }
        }
    }
}
