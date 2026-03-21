#!/bin/sh
set -e

PLUGIN_NAME="vault-plugin-secrets-honeycombio"
PLUGIN_PATH="/openbao/plugins/${PLUGIN_NAME}"
MOUNT_PATH="honeycomb"

# Start OpenBao dev server in background
bao server -dev \
  -dev-root-token-id=root \
  -dev-plugin-dir=/openbao/plugins \
  -dev-listen-address=0.0.0.0:8200 &

# Wait for OpenBao to be ready
echo "Waiting for OpenBao..."
export BAO_ADDR="http://127.0.0.1:8200"
export BAO_TOKEN="root"
until bao status > /dev/null 2>&1; do
  sleep 0.5
done
echo "OpenBao is ready."

# Register and enable the plugin
SHA256=$(sha256sum "${PLUGIN_PATH}" | cut -d' ' -f1)
bao plugin register -sha256="${SHA256}" secret "${PLUGIN_NAME}"
bao secrets enable -path="${MOUNT_PATH}" "${PLUGIN_NAME}"

# Configure if credentials are available
if [ -n "${HONEYCOMB_KEY_ID}" ] && [ -n "${HONEYCOMB_KEY_SECRET}" ]; then
  echo "Configuring Honeycomb backend..."
  bao write "${MOUNT_PATH}/config" \
    api_key_id="${HONEYCOMB_KEY_ID}" \
    api_key_secret="${HONEYCOMB_KEY_SECRET}"

  if [ -n "${HONEYCOMB_ENVIRONMENT}" ]; then
    echo "Creating sample ingest-test role..."
    bao write "${MOUNT_PATH}/roles/ingest-test" \
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
echo "OpenBao dev server running at http://localhost:8200 (token: root)"
echo "  bao read ${MOUNT_PATH}/creds/ingest-test"
echo ""

# Keep the container running
wait
