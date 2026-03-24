// SPDX-License-Identifier: GPL-2.0-or-later

//! ConfigApplicator — Ring 3 config diff and apply logic.
//!
//! Tracks the currently-active [`NodeConfig`] and computes a [`ConfigDiff`]
//! whenever a new config is applied. The diff describes which top-level fields
//! changed and which services were added, removed, or updated, enabling the
//! Ring 3 supervisor to perform minimal, targeted service restarts rather than
//! tearing down and rebuilding the entire node on every config change.

use std::collections::HashMap;

use harmony_microkernel::node_config::{NodeConfig, ServiceEntry};

// ── ConfigDiff ────────────────────────────────────────────────────────

/// Describes what changed between two [`NodeConfig`] snapshots.
///
/// Produced by [`ConfigDiff::compute`] and returned from
/// [`ConfigApplicator::apply`]. All `Vec` fields are sorted for
/// deterministic output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDiff {
    /// The `kernel` CID changed.
    pub kernel_changed: bool,
    /// The `identity` CID changed.
    pub identity_changed: bool,
    /// Any field inside [`NetworkConfig`] changed.
    pub network_changed: bool,
    /// Services present in the new config but absent from the old config.
    pub services_added: Vec<String>,
    /// Services present in the old config but absent from the new config.
    pub services_removed: Vec<String>,
    /// Services present in both configs but with a different `binary` or
    /// `config` CID.
    pub services_updated: Vec<String>,
}

impl ConfigDiff {
    /// Compute the diff between `old` and `new`.
    ///
    /// Services are matched by [`ServiceEntry::name`]. A service is
    /// considered *updated* if its `binary` or `config` field differs
    /// between the two configs.
    pub fn compute(old: &NodeConfig, new: &NodeConfig) -> Self {
        let kernel_changed = old.kernel != new.kernel;
        let identity_changed = old.identity != new.identity;
        let network_changed = old.network != new.network;

        let old_services: HashMap<&str, &ServiceEntry> =
            old.services.iter().map(|s| (s.name.as_str(), s)).collect();
        let new_services: HashMap<&str, &ServiceEntry> =
            new.services.iter().map(|s| (s.name.as_str(), s)).collect();

        let mut services_added = Vec::new();
        let mut services_updated = Vec::new();
        for (name, new_svc) in &new_services {
            match old_services.get(name) {
                None => services_added.push((*name).to_owned()),
                Some(old_svc) => {
                    if old_svc.binary != new_svc.binary || old_svc.config != new_svc.config {
                        services_updated.push((*name).to_owned());
                    }
                }
            }
        }

        let mut services_removed = Vec::new();
        for name in old_services.keys() {
            if !new_services.contains_key(name) {
                services_removed.push((*name).to_owned());
            }
        }

        services_added.sort();
        services_removed.sort();
        services_updated.sort();

        Self {
            kernel_changed,
            identity_changed,
            network_changed,
            services_added,
            services_removed,
            services_updated,
        }
    }
}

// ── ConfigApplicator ──────────────────────────────────────────────────

/// Tracks the active [`NodeConfig`] and produces a [`ConfigDiff`] on
/// each transition.
///
/// On the first call to [`apply`][ConfigApplicator::apply] there is no
/// previous config, so all fields are treated as changed and every
/// service is reported as added.
pub struct ConfigApplicator {
    active: Option<NodeConfig>,
}

impl ConfigApplicator {
    /// Create a new applicator with no active config.
    pub fn new() -> Self {
        Self { active: None }
    }

    /// Apply `new_config`, compute and return the diff relative to the
    /// previously-active config (or a "first boot" diff if none exists),
    /// then store `new_config` as the new active config.
    pub fn apply(&mut self, new_config: NodeConfig) -> ConfigDiff {
        let diff = match &self.active {
            Some(old) => ConfigDiff::compute(old, &new_config),
            None => {
                // First apply: treat everything as new.
                let mut services_added: Vec<String> =
                    new_config.services.iter().map(|s| s.name.clone()).collect();
                services_added.sort();
                ConfigDiff {
                    kernel_changed: true,
                    identity_changed: true,
                    network_changed: true,
                    services_added,
                    services_removed: Vec::new(),
                    services_updated: Vec::new(),
                }
            }
        };
        self.active = Some(new_config);
        diff
    }

    /// Return a reference to the currently-active config, if any.
    pub fn active(&self) -> Option<&NodeConfig> {
        self.active.as_ref()
    }
}

impl Default for ConfigApplicator {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use harmony_microkernel::node_config::{NetworkConfig, SCHEMA_VERSION};

    use super::*;

    fn base_config() -> NodeConfig {
        NodeConfig {
            version: SCHEMA_VERSION,
            kernel: [1u8; 32],
            identity: [2u8; 32],
            network: NetworkConfig {
                mesh_seeds: vec![[0xAB; 16]],
                port: 7777,
            },
            services: vec![
                ServiceEntry {
                    name: "echo".to_owned(),
                    binary: [10u8; 32],
                    config: None,
                },
                ServiceEntry {
                    name: "content".to_owned(),
                    binary: [20u8; 32],
                    config: Some([21u8; 32]),
                },
            ],
        }
    }

    #[test]
    fn identical_configs_produce_empty_diff() {
        let old = base_config();
        let new = base_config();
        let diff = ConfigDiff::compute(&old, &new);
        assert!(!diff.kernel_changed);
        assert!(!diff.identity_changed);
        assert!(!diff.network_changed);
        assert!(diff.services_added.is_empty());
        assert!(diff.services_removed.is_empty());
        assert!(diff.services_updated.is_empty());
    }

    #[test]
    fn kernel_change_detected() {
        let old = base_config();
        let mut new = base_config();
        new.kernel = [0xFFu8; 32];
        let diff = ConfigDiff::compute(&old, &new);
        assert!(diff.kernel_changed);
        assert!(!diff.identity_changed);
        assert!(!diff.network_changed);
    }

    #[test]
    fn identity_change_detected() {
        let old = base_config();
        let mut new = base_config();
        new.identity = [0xEEu8; 32];
        let diff = ConfigDiff::compute(&old, &new);
        assert!(!diff.kernel_changed);
        assert!(diff.identity_changed);
        assert!(!diff.network_changed);
    }

    #[test]
    fn network_port_change_detected() {
        let old = base_config();
        let mut new = base_config();
        new.network.port = 9999;
        let diff = ConfigDiff::compute(&old, &new);
        assert!(!diff.kernel_changed);
        assert!(!diff.identity_changed);
        assert!(diff.network_changed);
    }

    #[test]
    fn service_added() {
        let old = base_config();
        let mut new = base_config();
        new.services.push(ServiceEntry {
            name: "dns".to_owned(),
            binary: [30u8; 32],
            config: None,
        });
        let diff = ConfigDiff::compute(&old, &new);
        assert_eq!(diff.services_added, vec!["dns".to_owned()]);
        assert!(diff.services_removed.is_empty());
        assert!(diff.services_updated.is_empty());
    }

    #[test]
    fn service_removed() {
        let old = base_config();
        let mut new = base_config();
        new.services.retain(|s| s.name != "echo");
        let diff = ConfigDiff::compute(&old, &new);
        assert!(diff.services_added.is_empty());
        assert_eq!(diff.services_removed, vec!["echo".to_owned()]);
        assert!(diff.services_updated.is_empty());
    }

    #[test]
    fn service_updated() {
        let old = base_config();
        let mut new = base_config();
        // Change the binary CID for "content"
        for svc in &mut new.services {
            if svc.name == "content" {
                svc.binary = [0xDDu8; 32];
            }
        }
        let diff = ConfigDiff::compute(&old, &new);
        assert!(diff.services_added.is_empty());
        assert!(diff.services_removed.is_empty());
        assert_eq!(diff.services_updated, vec!["content".to_owned()]);
    }

    #[test]
    fn applicator_tracks_active_config() {
        let mut app = ConfigApplicator::new();
        assert!(app.active().is_none());
        let cfg = base_config();
        app.apply(cfg.clone());
        assert_eq!(app.active(), Some(&cfg));
    }

    #[test]
    fn applicator_second_apply_computes_diff() {
        let mut app = ConfigApplicator::new();
        let first = base_config();
        // First apply: first-boot diff — all services added
        let diff1 = app.apply(first);
        assert!(diff1.kernel_changed);
        assert!(diff1.identity_changed);
        assert!(diff1.network_changed);
        let mut expected_added = vec!["content".to_owned(), "echo".to_owned()];
        expected_added.sort();
        assert_eq!(diff1.services_added, expected_added);

        // Second apply: only port changed
        let mut second = base_config();
        second.network.port = 8888;
        let diff2 = app.apply(second);
        assert!(!diff2.kernel_changed);
        assert!(!diff2.identity_changed);
        assert!(diff2.network_changed);
        assert!(diff2.services_added.is_empty());
        assert!(diff2.services_removed.is_empty());
        assert!(diff2.services_updated.is_empty());
    }
}
