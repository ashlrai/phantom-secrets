use serde::{Deserialize, Serialize};

/// Closed operations whose effect is derived by Phantom, never supplied by a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    AssumePlace,
    Capability,
    FixAuth,
    InspectWorkspace,
    Leave,
    NeedSecret,
    RunEngineeringCheck,
    SetupWorkspace,
    Share,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    Inspect,
    LocalRead,
    LocalWrite,
    ExternalWrite,
    SecretUse,
}

impl Operation {
    pub const fn effect_class(self) -> EffectClass {
        match self {
            Self::Capability => EffectClass::Inspect,
            Self::InspectWorkspace => EffectClass::LocalRead,
            Self::AssumePlace
            | Self::FixAuth
            | Self::Leave
            | Self::RunEngineeringCheck
            | Self::SetupWorkspace => EffectClass::LocalWrite,
            Self::NeedSecret => EffectClass::SecretUse,
            Self::Share => EffectClass::ExternalWrite,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broad_and_secret_reveal_operations_are_not_deserializable() {
        for denied in ["do", "need_power", "secret_reveal", "future_power"] {
            assert!(serde_json::from_str::<Operation>(&format!("\"{denied}\"")).is_err());
        }
    }

    #[test]
    fn effects_are_derived_from_closed_operations() {
        assert_eq!(Operation::Capability.effect_class(), EffectClass::Inspect);
        assert_eq!(Operation::Share.effect_class(), EffectClass::ExternalWrite);
        assert_eq!(Operation::NeedSecret.effect_class(), EffectClass::SecretUse);
        assert_eq!(
            Operation::RunEngineeringCheck.effect_class(),
            EffectClass::LocalWrite
        );
    }
}
