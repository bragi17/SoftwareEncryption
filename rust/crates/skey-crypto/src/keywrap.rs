use hkdf::Hkdf;
use sha2::Sha256;

pub fn derive_file_key(
    package_key: &[u8; 32],
    package_id: &str,
    blob_id: &str,
    version: &str,
) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(package_id.as_bytes()), package_key);
    let info = format!("file|{blob_id}|{version}");
    let mut file_key = [0u8; 32];
    hkdf.expand(info.as_bytes(), &mut file_key)
        .expect("32-byte HKDF output is valid");
    file_key
}
