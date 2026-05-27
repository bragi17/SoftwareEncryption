use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct Manifest {
    pub format: String,
    pub product_id: String,
    pub package_id: String,
    pub version: String,
    pub created_at: String,
    pub builder_version: String,
    pub min_runtime_version: String,
    pub crypto: CryptoManifest,
    pub entrypoints: Vec<EntryPointManifest>,
    pub blobs: Vec<BlobManifest>,
    pub runtime: RuntimeManifest,
    pub signature: SignatureManifest,
}

#[derive(Clone, Debug, Deserialize)]
pub struct CryptoManifest {
    pub aead: String,
    pub kdf: String,
    pub signature: String,
    pub nonce_policy: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct EntryPointManifest {
    pub id: String,
    pub path: String,
    pub kind: String,
    pub feature: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BlobManifest {
    pub blob_id: String,
    #[serde(rename = "type")]
    pub blob_type: String,
    pub original_path: String,
    pub offset: u64,
    pub cipher_len: u64,
    pub plain_len: u64,
    #[serde(default)]
    pub nonce: Option<String>,
    pub aad: String,
    pub sha256_plain: String,
    pub feature: String,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub chunk_size: Option<u64>,
    #[serde(default)]
    pub chunk_count: Option<u64>,
    #[serde(default)]
    pub chunks: Vec<BlobChunkManifest>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BlobChunkManifest {
    pub nonce: String,
    pub offset: u64,
    pub cipher_len: u64,
    pub plain_len: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RuntimeManifest {
    pub required_dlls: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SignatureManifest {
    pub kid: String,
    pub alg: String,
    pub sig: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BlobTableEntry {
    pub blob_id: String,
    pub offset: u64,
    pub cipher_len: u64,
}
