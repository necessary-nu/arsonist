use std::fmt;

use anyhow::{Result, bail};

/// An image reference: `[registry/]repository[:tag][@sha256:…]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub registry: String,
    pub repository: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

pub fn valid_digest(digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

impl Reference {
    pub fn parse(text: &str) -> Result<Reference> {
        let (rest, digest) = match text.split_once('@') {
            Some((rest, digest)) => {
                if !valid_digest(digest) {
                    bail!("{text}: the digest must be sha256:<64 hex digits>");
                }
                (rest, Some(digest.to_string()))
            }
            None => (text, None),
        };
        let (name, tag) = match rest.rsplit_once(':') {
            Some((name, tag)) if !tag.contains('/') => (name, Some(tag)),
            _ => (rest, None),
        };
        let (registry, repository) = match name.split_once('/') {
            Some((first, path)) if first.contains(['.', ':']) || first == "localhost" => {
                (first, path)
            }
            _ => ("docker.io", name),
        };
        let registry = match registry {
            "index.docker.io" | "registry-1.docker.io" => "docker.io",
            r => r,
        };
        let repository = if registry == "docker.io" && !repository.contains('/') {
            format!("library/{repository}")
        } else {
            repository.to_string()
        };

        let component_ok = |c: &str| {
            !c.is_empty()
                && c.bytes()
                    .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
                && c.as_bytes()[0].is_ascii_alphanumeric()
        };
        if !repository.split('/').all(component_ok) {
            bail!(
                "{text}: the repository must be lowercase letters, digits, '.', '_', '-' and '/'"
            );
        }
        if let Some(tag) = tag {
            let tag_ok = !tag.is_empty()
                && tag.len() <= 128
                && tag
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
                && tag.as_bytes()[0] != b'.'
                && tag.as_bytes()[0] != b'-';
            if !tag_ok {
                bail!("{text}: {tag:?} is not a valid tag");
            }
        }
        Ok(Reference {
            registry: registry.to_string(),
            repository,
            tag: tag.map(String::from),
            digest,
        })
    }

    pub fn api_host(&self) -> &str {
        if self.registry == "docker.io" {
            "registry-1.docker.io"
        } else {
            &self.registry
        }
    }

    /// `registry/repository`, without tag or digest.
    pub fn name(&self) -> String {
        format!("{}/{}", self.registry, self.repository)
    }

    /// What to ask the registry for: the digest if pinned, else the tag.
    pub fn manifest_reference(&self) -> &str {
        self.digest
            .as_deref()
            .or(self.tag.as_deref())
            .unwrap_or("latest")
    }

    /// The same image, pinned: `registry/repository@digest`.
    pub fn pinned(&self, digest: &str) -> String {
        format!("{}@{digest}", self.name())
    }
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.name())?;
        if let Some(tag) = &self.tag {
            write!(f, ":{tag}")?;
        }
        if let Some(digest) = &self.digest {
            write!(f, "@{digest}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parts(text: &str) -> (String, String, Option<String>, Option<String>) {
        let r = Reference::parse(text).unwrap();
        (r.registry, r.repository, r.tag, r.digest)
    }

    const D: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn references_parse_as_docker_reads_them() {
        assert_eq!(
            parts("ghcr.io/divvun/divvun-actions:ubuntu-latest"),
            (
                "ghcr.io".into(),
                "divvun/divvun-actions".into(),
                Some("ubuntu-latest".into()),
                None
            )
        );
        assert_eq!(
            parts("alpine"),
            ("docker.io".into(), "library/alpine".into(), None, None)
        );
        assert_eq!(
            parts("library/alpine:3"),
            (
                "docker.io".into(),
                "library/alpine".into(),
                Some("3".into()),
                None
            )
        );
        assert_eq!(
            parts("localhost:5000/x/y:1"),
            (
                "localhost:5000".into(),
                "x/y".into(),
                Some("1".into()),
                None
            )
        );
        assert_eq!(
            parts("localhost:5000/x/y"),
            ("localhost:5000".into(), "x/y".into(), None, None)
        );
        assert_eq!(
            parts(&format!("ghcr.io/a/b:t@{D}")),
            (
                "ghcr.io".into(),
                "a/b".into(),
                Some("t".into()),
                Some(D.into())
            )
        );
        assert_eq!(parts("index.docker.io/library/debian").0, "docker.io");
    }

    #[test]
    fn manifests_are_fetched_by_digest_when_pinned() {
        let r = Reference::parse(&format!("ghcr.io/a/b:t@{D}")).unwrap();
        assert_eq!(r.manifest_reference(), D);
        assert_eq!(
            Reference::parse("alpine").unwrap().manifest_reference(),
            "latest"
        );
        assert_eq!(
            Reference::parse("alpine").unwrap().api_host(),
            "registry-1.docker.io"
        );
        assert_eq!(r.pinned(D), format!("ghcr.io/a/b@{D}"));
        assert_eq!(r.to_string(), format!("ghcr.io/a/b:t@{D}"));
    }

    #[test]
    fn bad_references_are_refused() {
        assert!(Reference::parse("ghcr.io/Divvun/x").is_err());
        assert!(Reference::parse("ghcr.io/a/b@sha256:abc").is_err());
        assert!(Reference::parse("ghcr.io/a/b:-bad").is_err());
        assert!(Reference::parse("ghcr.io//b").is_err());
    }
}
