// SPDX-License-Identifier: GPL-2.0-or-later

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use harmony_platform::{PersistentState, PlatformError};

pub struct MemoryState {
    store: BTreeMap<String, Vec<u8>>,
}

impl MemoryState {
    pub fn new() -> Self {
        MemoryState {
            store: BTreeMap::new(),
        }
    }
}

impl Default for MemoryState {
    fn default() -> Self {
        Self::new()
    }
}

impl PersistentState for MemoryState {
    fn save(&mut self, key: &str, data: &[u8]) -> Result<(), PlatformError> {
        self.store.insert(key.into(), data.to_vec());
        Ok(())
    }

    fn load(&self, key: &str) -> Option<Vec<u8>> {
        self.store.get(key).cloned()
    }

    fn delete(&mut self, key: &str) -> Result<(), PlatformError> {
        self.store.remove(key);
        Ok(())
    }

    fn keys(&self) -> Vec<String> {
        self.store.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_and_load_round_trip() {
        let mut state = MemoryState::new();
        state.save("identity", b"key-material-64-bytes").unwrap();
        assert_eq!(state.load("identity").unwrap(), b"key-material-64-bytes");
    }

    #[test]
    fn load_missing_returns_none() {
        let state = MemoryState::new();
        assert!(state.load("nonexistent").is_none());
    }

    #[test]
    fn save_overwrites() {
        let mut state = MemoryState::new();
        state.save("config", b"v1").unwrap();
        state.save("config", b"v2").unwrap();
        assert_eq!(state.load("config").unwrap(), b"v2");
    }

    #[test]
    fn delete_removes_key() {
        let mut state = MemoryState::new();
        state.save("temp", b"data").unwrap();
        state.delete("temp").unwrap();
        assert!(state.load("temp").is_none());
    }

    #[test]
    fn delete_missing_is_noop() {
        let mut state = MemoryState::new();
        state.delete("ghost").unwrap();
    }

    #[test]
    fn keys_lists_all_sorted() {
        let mut state = MemoryState::new();
        state.save("zebra", b"z").unwrap();
        state.save("alpha", b"a").unwrap();
        state.save("middle", b"m").unwrap();
        assert_eq!(state.keys(), vec!["alpha", "middle", "zebra"]);
    }

    #[test]
    fn works_as_trait_object() {
        let mut state = MemoryState::new();
        let ps: &mut dyn PersistentState = &mut state;
        ps.save("via-dyn", b"dynamic").unwrap();
        assert_eq!(ps.load("via-dyn").unwrap(), b"dynamic");
    }
}
