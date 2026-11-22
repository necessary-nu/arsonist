#!/usr/bin/env bash
# The agent against the real things: OpenBao's dev server holding the
# transit key, an AppRole allowed only to read and sign with it, and sshd
# trusting the key as `bao-ssh-agent public-key` prints it. OpenSSH logs in
# through `bao-ssh-agent serve`, then again after every AppRole token is
# revoked, which the agent must log in again for. Needs Docker.
set -euo pipefail

repo=$(cd "$(dirname "$0")/../../.." && pwd)
bao=arsonist-bao-$$

docker run -d --rm --name "$bao" ghcr.io/openbao/openbao:2.7.1 \
  server -dev -dev-root-token-id=root -dev-listen-address=127.0.0.1:8200 >/dev/null
trap 'docker rm -f "$bao" >/dev/null' EXIT

docker run --rm -i --network "container:$bao" -v "$repo:/src" \
  -v arsonist-target:/target -v arsonist-cargo:/usr/local/cargo/registry \
  -e CARGO_TARGET_DIR=/target -w /src rust:1 bash -s <<'INNER'
set -euo pipefail
apt-get update -qq && apt-get install -y -qq jq openssh-server >/dev/null
cargo build -q -p bao-ssh-agent
agent=/target/debug/bao-ssh-agent

api() {
  local method=$1 path=$2 body=${3:-}
  curl -fsS -X "$method" -H "X-Vault-Token: root" ${body:+-d "$body"} "http://127.0.0.1:8200/v1/$path"
}
until curl -fsS http://127.0.0.1:8200/v1/sys/health >/dev/null 2>&1; do sleep 1; done
api POST sys/mounts/transit '{"type": "transit"}'
api POST transit/keys/buildkite-ssh '{"type": "ed25519"}' >/dev/null
api PUT sys/policies/acl/arsonist-ssh "$(jq -n --arg p '
path "transit/keys/buildkite-ssh" { capabilities = ["read"] }
path "transit/sign/buildkite-ssh" { capabilities = ["update"] }' '{policy: $p}')"
api POST sys/auth/approle '{"type": "approle"}'
api POST auth/approle/role/arsonist '{"token_policies": ["arsonist-ssh"], "token_ttl": "1h"}'
role_id=$(api GET auth/approle/role/arsonist/role-id | jq -r .data.role_id)
secret_id=$(api POST auth/approle/role/arsonist/secret-id | jq -r .data.secret_id)
jq -n --arg r "$role_id" --arg s "$secret_id" '{role_id: $r, secret_id: $s}' >/tmp/approle.json
chmod 600 /tmp/approle.json

export BAO_ADDR=http://127.0.0.1:8200 BAO_SSH_AGENT_KEY=buildkite-ssh
export BAO_SSH_AGENT_APPROLE_FILE=/tmp/approle.json

mkdir -p /root/.ssh /run/sshd && chmod 700 /root/.ssh
$agent public-key | tee /root/.ssh/authorized_keys
ssh-keygen -A >/dev/null
/usr/sbin/sshd -p 2222 -o PermitRootLogin=prohibit-password -o PasswordAuthentication=no

$agent serve --socket /tmp/agent.sock 2>/tmp/agent.log &
until [ -S /tmp/agent.sock ]; do sleep 0.1; done
export SSH_AUTH_SOCK=/tmp/agent.sock
login() {
  ssh -n -p 2222 -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR root@127.0.0.1 "echo logged in as \$(whoami)"
}
ssh-add -l
login

# Every token the AppRole logins issued, gone: the agent's next call is
# refused, and it has to log in again.
api PUT sys/leases/revoke-prefix/auth/approle/login
login

echo "--- agent log ---"
cat /tmp/agent.log
[ "$(grep -c 'signed with transit/buildkite-ssh v1' /tmp/agent.log)" = 2 ]
echo "--- ssh agent e2e passed ---"
INNER
