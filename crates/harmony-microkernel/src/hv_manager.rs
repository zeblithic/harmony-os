// SPDX-License-Identifier: GPL-2.0-or-later
//! VM lifecycle types for the 9P VmServer.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmCommand {
    Start { entry_ipa: u64, dtb_ipa: u64 },
    Destroy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    Created,
    Running,
    Halted,
}

impl VmState {
    pub fn as_str(&self) -> &'static str {
        match self {
            VmState::Created => "created\n",
            VmState::Running => "running\n",
            VmState::Halted => "halted\n",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vm_state_as_str() {
        assert_eq!(VmState::Created.as_str(), "created\n");
        assert_eq!(VmState::Running.as_str(), "running\n");
        assert_eq!(VmState::Halted.as_str(), "halted\n");
    }

    #[test]
    fn vm_command_eq() {
        assert_eq!(
            VmCommand::Start { entry_ipa: 0x4000_0000, dtb_ipa: 0x4400_0000 },
            VmCommand::Start { entry_ipa: 0x4000_0000, dtb_ipa: 0x4400_0000 },
        );
        assert_ne!(VmCommand::Destroy, VmCommand::Start { entry_ipa: 0, dtb_ipa: 0 });
    }
}
