#!/bin/sh
set -e

PLUGIN_NAME="vault-plugin-secrets-honeycombio"
PLUGIN_PATH="/vault/plugins/${PLUGIN_NAME}"
MOUNT_PATH="honeycomb"

# Start Vault dev server in background
vault server -dev \
  -dev-root-token-id=root \
  -dev-plugin-dir=/vault/plugins \
  -dev-listen-address=0.0.0.0:8200 &

# Wait for Vault to be ready
echo "Waiting for Vault..."
until vault status > /dev/null 2>&1; do
  sleep 0.5
done
echo "Vault is ready."

export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="root"

# Register and enable the plugin
SHA256=$(sha256sum "${PLUGIN_PATH}" | cut -d' ' -f1)
vault plugin register -sha256="${SHA256}" secret "${PLUGIN_NAME}"
vault secrets enable -path="${MOUNT_PATH}" "${PLUGIN_NAME}"

# Configure if credentials are available
if [ -n "${HONEYCOMB_KEY_ID}" ] && [ -n "${HONEYCOMB_KEY_SECRET}" ]; then
  echo "Configuring Honeycomb backend..."
  vault write "${MOUNT_PATH}/config" \
    api_key_id="${HONEYCOMB_KEY_ID}" \
    api_key_secret="${HONEYCOMB_KEY_SECRET}"

  if [ -n "${HONEYCOMB_ENVIRONMENT}" ]; then
    echo "Creating sample ingest-test role..."
    vault write "${MOUNT_PATH}/roles/ingest-test" \
      key_type=ingest \
      environment="${HONEYCOMB_ENVIRONMENT}" \
      create_datasets=true \
      ttl=1h \
      max_ttl=24h
  fi

  echo "Honeycomb plugin configured and ready."
else
  echo "HONEYCOMB_KEY_ID/HONEYCOMB_KEY_SECRET not set — plugin enabled but not configured."
fi

echo ""
echo "Vault dev server running at http://localhost:8200 (token: root)"
echo "  vault read ${MOUNT_PATH}/creds/ingest-test"
echo ""

# Keep the container running
wait
