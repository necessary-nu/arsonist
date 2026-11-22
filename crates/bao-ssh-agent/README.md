# bao-ssh-agent

An ssh agent whose one key is an Ed25519 key in OpenBao's transit engine.
It never holds the key: for each signature ssh asks of it, it asks OpenBao.
Whoever can reach the agent can use the key while it runs, and nobody can
take the key away, so a build machine can clone over ssh without a private
key on its disk.

The agent speaks the protocol through
[ssh-agent-lib](https://crates.io/crates/ssh-agent-lib), on a unix socket,
or on Windows a named pipe. It offers the key's latest version, looked up
once, and signs with nothing else. It logs every signature.

## Running it

```sh
export BAO_ADDR=https://vault.example BAO_SSH_AGENT_KEY=buildkite-ssh
bao-ssh-agent public-key       # an authorized_keys line, for the git host
bao-ssh-agent serve --socket /run/bao-ssh-agent.sock &
SSH_AUTH_SOCK=/run/bao-ssh-agent.sock git clone git@github.com:org/repo.git
```

On Windows, `bao-ssh-agent serve` listens at `\\.\pipe\openssh-ssh-agent`,
where Windows' OpenSSH looks, unless given `--pipe`.

It logs in with an AppRole whose role and secret ids are in a file, read at
every login, so a new secret id needs no restart:

```sh
echo '{"role_id": "…", "secret_id": "…"}' | install -m 600 /dev/stdin /etc/bao-ssh-agent.json
bao-ssh-agent --approle-file /etc/bao-ssh-agent.json serve --socket …
```

Without `--approle-file` it uses the token in `BAO_TOKEN`, such as a
person's from `bao login`.

## Setting up OpenBao

The key, made in OpenBao so it has never been anywhere else, and an AppRole
that may use it and do nothing more:

```sh
bao write -f transit/keys/buildkite-ssh type=ed25519
bao policy write bao-ssh-agent - <<'EOF'
path "transit/keys/buildkite-ssh" { capabilities = ["read"] }
path "transit/sign/buildkite-ssh" { capabilities = ["update"] }
EOF
bao write auth/approle/role/bao-ssh-agent token_policies=bao-ssh-agent token_ttl=1h
bao read auth/approle/role/bao-ssh-agent/role-id
bao write -f auth/approle/role/bao-ssh-agent/secret-id
```

## As a library

`Agent` is an ssh-agent-lib `Session` over any `KeyStore`, of which
`Transit` is the real one. A program without an async runtime of its own
can serve agents from a `Background`, one `Serving` per listener, which
stops listening when dropped. arsonist does that for each VM it boots.

## Testing

`cargo test` covers the agent with a key in memory.
`scripts/e2e.sh` runs it against OpenBao's dev server and logs in to sshd
through it, before and after OpenBao revokes the agent's token. It needs
Docker.

## Licence

EUPL-1.2. See [LICENSE](../../LICENSE).
