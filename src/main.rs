mod error;
mod hardware_key;
mod recovery_key;
mod vault;

pub use hardware_key::HardwareKey;
pub use recovery_key::RecoveryKey;
pub use vault::Vault;

fn main() {
    let mut key = HardwareKey::new("/dev/ttyACM0", 9600, 0).unwrap();
    let vault = Vault
}
