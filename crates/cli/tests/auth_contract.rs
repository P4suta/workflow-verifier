use std::collections::BTreeMap;
use std::sync::Mutex;
use workflow_verifier_cli::auth::{
    AuthService, CredentialKey, CredentialStore, ProviderKind, SecretString,
};

#[derive(Default)]
struct MemoryStore(Mutex<BTreeMap<CredentialKey, String>>);

impl CredentialStore for MemoryStore {
    fn put(&self, key: &CredentialKey, secret: &SecretString) -> Result<(), String> {
        self.0
            .lock()
            .unwrap()
            .insert(key.clone(), secret.expose().to_owned());
        Ok(())
    }

    fn get(&self, key: &CredentialKey) -> Result<Option<SecretString>, String> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(key)
            .map(|value| SecretString::new(value.clone()).unwrap()))
    }

    fn delete(&self, key: &CredentialKey) -> Result<bool, String> {
        Ok(self.0.lock().unwrap().remove(key).is_some())
    }
}

#[test]
fn provider_hosts_are_canonical_and_reject_url_or_ip_syntax() {
    let github = CredentialKey::new(ProviderKind::Github, None).unwrap();
    assert_eq!(github.host(), "github.com");
    assert_eq!(github.identity(), "github@github.com");
    assert_eq!(
        CredentialKey::new(ProviderKind::Gitlab, Some("Git.EXAMPLE.test:443"))
            .unwrap()
            .host(),
        "git.example.test"
    );
    for host in [
        "https://github.com",
        "user@github.com",
        "127.0.0.1",
        "localhost",
        "host/path",
    ] {
        assert!(CredentialKey::new(ProviderKind::Github, Some(host)).is_err());
    }
}

#[test]
fn secrets_are_redacted_and_store_round_trips_without_plaintext_fallback() {
    let secret = SecretString::new("top-secret-token").unwrap();
    assert_eq!(format!("{secret:?}"), "SecretString([REDACTED])");
    assert!(!format!("{secret:?}").contains(secret.expose()));
    assert!(SecretString::new("line\nbreak").is_err());

    let key = CredentialKey::new(ProviderKind::Github, None).unwrap();
    let service = AuthService::new(MemoryStore::default());
    service.login(&key, &secret).unwrap();
    assert!(service.status(&key).unwrap());
    let loaded = service.credential(&key).unwrap().unwrap();
    assert_eq!(loaded.expose(), "top-secret-token");
    assert!(service.logout(&key).unwrap());
    assert!(!service.status(&key).unwrap());
}

#[test]
fn provider_parser_covers_exactly_the_four_supported_frontends() {
    for name in ["github", "gitlab", "azure", "circleci"] {
        assert_eq!(ProviderKind::parse(name).unwrap().name(), name);
    }
    assert!(ProviderKind::parse("other").is_err());
}
