// SPDX-License-Identifier: GPL-2.0-or-later
//! End-to-end integration test for the config lifecycle:
//! Build → Sign → Ingest → Stage → Commit → Read back → Verify.

use std::sync::Arc;

use harmony_identity::PqPrivateIdentity;
use harmony_microkernel::config_server::ConfigServer;
use harmony_microkernel::content_server::{format_cid_hex, ContentServer};
use harmony_microkernel::node_config::{NetworkConfig, NodeConfig, ServiceEntry, SCHEMA_VERSION};
use harmony_microkernel::signed_config::SignedConfig;
use harmony_microkernel::{FileServer, OpenMode};
use rand::rngs::OsRng;

/// Ingest bytes into ContentServer via 9P, return the CID.
fn ingest(cas: &mut ContentServer, data: &[u8], fid: u32) -> [u8; 32] {
    cas.walk(0, fid, "ingest").unwrap();
    cas.open(fid, OpenMode::ReadWrite).unwrap();
    cas.write(fid, 0, data).unwrap();
    let resp = cas.read(fid, 0, 256).unwrap();
    cas.clunk(fid).unwrap();
    resp[..32].try_into().unwrap()
}

#[test]
fn full_config_lifecycle() {
    // 1. Create operator identity
    let operator = PqPrivateIdentity::generate(&mut OsRng);
    let pub_id = operator.public_identity();

    // 2. Create stub content for referenced CIDs
    let mut cas = ContentServer::new();
    let kernel_cid = ingest(&mut cas, &[0x4Bu8; 4096], 1);
    let identity_cid = ingest(&mut cas, &[0x49u8; 4096], 2);
    let binary_cid = ingest(&mut cas, &[0x53u8; 4096], 3);

    // 3. Build NodeConfig
    let config = NodeConfig {
        version: SCHEMA_VERSION,
        kernel: kernel_cid,
        identity: identity_cid,
        network: NetworkConfig {
            mesh_seeds: vec![[0x01; 16]],
            port: 4242,
        },
        services: vec![ServiceEntry {
            name: String::from("echo"),
            binary: binary_cid,
            config: None,
        }],
    };

    // 4. Sign it
    let config_bytes = config.to_cbor();
    let signature = operator.sign(&config_bytes).unwrap();
    let signed = SignedConfig {
        config_bytes: config_bytes.clone(),
        signature,
        signer: pub_id.address_hash,
        signer_pubkey: pub_id.to_public_bytes(),
    };

    // 5. Verify config CID stability
    let config_cid = config.cid();
    assert_eq!(config_cid, harmony_athenaeum::sha256_hash(&config_bytes));

    // 6. Ingest SignedConfig into CAS
    let signed_cbor = signed.to_cbor();
    let signed_cid = ingest(&mut cas, &signed_cbor, 4);

    // 7. Create ConfigServer, stage + commit
    let cas = Arc::new(cas);
    let trusted = vec![pub_id.address_hash];
    let mut cfg_server = ConfigServer::new(cas, trusted);

    // Stage
    let hex = format_cid_hex(&signed_cid);
    cfg_server.walk(0, 10, "stage").unwrap();
    cfg_server.open(10, OpenMode::Write).unwrap();
    cfg_server.write(10, 0, hex.as_bytes()).unwrap();
    cfg_server.clunk(10).unwrap();

    // Commit
    cfg_server.walk(0, 11, "commit").unwrap();
    cfg_server.open(11, OpenMode::Write).unwrap();
    cfg_server.write(11, 0, b"1").unwrap();
    cfg_server.clunk(11).unwrap();

    // 8. Read back active CID
    cfg_server.walk(0, 20, "active").unwrap();
    cfg_server.open(20, OpenMode::Read).unwrap();
    let active_hex = cfg_server.read(20, 0, 256).unwrap();
    cfg_server.clunk(20).unwrap();
    assert_eq!(
        core::str::from_utf8(&active_hex).unwrap(),
        &format_cid_hex(&signed_cid)
    );

    // 9. Read back node.cbor and verify
    cfg_server.walk(0, 30, "node.cbor").unwrap();
    cfg_server.open(30, OpenMode::Read).unwrap();
    let cbor = cfg_server.read(30, 0, 65536).unwrap();
    cfg_server.clunk(30).unwrap();

    let decoded = NodeConfig::from_cbor(&cbor).unwrap();
    assert_eq!(decoded, config);
    assert_eq!(decoded.cid(), config_cid);
}
