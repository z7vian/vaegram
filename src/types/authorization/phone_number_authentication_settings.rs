use crate::raw::{base, types};

/// Firebase delivery of the code, for official apps' use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirebaseAuthenticationSettings {
    Android,
    Ios { device_token: String, is_app_sandbox: bool },
}

/// How Telegram may deliver a phone number code. The default asks for nothing special.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PhoneNumberAuthenticationSettings {
    pub allow_flash_call: bool,
    pub allow_missed_call: bool,
    /// The number is the one this device is already using.
    pub is_current_phone_number: bool,
    /// The device has a SIM card but it can't be checked whether its number matches.
    pub has_unknown_phone_number: bool,
    pub allow_sms_retriever_api: bool,
    pub firebase_authentication_settings: Option<FirebaseAuthenticationSettings>,
    /// Tokens (up to 20) received in previously logged out sessions.
    pub authentication_tokens: Vec<Vec<u8>>,
}

impl PhoneNumberAuthenticationSettings {
    pub(crate) fn write(&self) -> base::CodeSettings {
        let (token, app_sandbox) = match &self.firebase_authentication_settings {
            Some(FirebaseAuthenticationSettings::Ios { device_token, is_app_sandbox }) => {
                (Some(device_token.clone()), Some(*is_app_sandbox))
            }
            _ => (None, None),
        };
        base::CodeSettings::CodeSettings(Box::new(types::CodeSettings {
            allow_flashcall: self.allow_flash_call,
            current_number: self.is_current_phone_number,
            allow_app_hash: self.allow_sms_retriever_api,
            allow_missed_call: self.allow_missed_call,
            allow_firebase: self.firebase_authentication_settings.is_some(),
            unknown_number: self.has_unknown_phone_number,
            logout_tokens: (!self.authentication_tokens.is_empty()).then(|| self.authentication_tokens.clone()),
            token,
            app_sandbox,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::{FirebaseAuthenticationSettings, PhoneNumberAuthenticationSettings};
    use crate::raw::base;

    fn written(settings: &PhoneNumberAuthenticationSettings) -> crate::raw::types::CodeSettings {
        let base::CodeSettings::CodeSettings(s) = settings.write();
        *s
    }

    #[test]
    fn settings_write_firebase_and_tokens() {
        let none = written(&PhoneNumberAuthenticationSettings::default());
        assert!(!none.allow_firebase && none.logout_tokens.is_none() && none.token.is_none());
        assert!(none.app_sandbox.is_none());

        let android = PhoneNumberAuthenticationSettings {
            firebase_authentication_settings: Some(FirebaseAuthenticationSettings::Android),
            ..Default::default()
        };
        let s = written(&android);
        assert!(s.allow_firebase && s.token.is_none() && s.app_sandbox.is_none());

        let ios = PhoneNumberAuthenticationSettings {
            allow_flash_call: true,
            is_current_phone_number: true,
            firebase_authentication_settings: Some(FirebaseAuthenticationSettings::Ios {
                device_token: "tok".into(),
                is_app_sandbox: true,
            }),
            authentication_tokens: vec![vec![1], vec![2, 3]],
            ..Default::default()
        };
        let s = written(&ios);
        assert!(s.allow_firebase && s.allow_flashcall && s.current_number);
        assert_eq!((s.token.as_deref(), s.app_sandbox), (Some("tok"), Some(true)));
        assert_eq!(s.logout_tokens, Some(vec![vec![1], vec![2, 3]]));
    }
}
