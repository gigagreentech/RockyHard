#!/usr/bin/env bash
set -euo pipefail

TARGET_HOST="${1:-root@172.26.124.219}"
REMOTE_DIR="/opt/hardening"
LOCAL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Stripping Windows line endings..."
find "$LOCAL_DIR" -name "*.sh" -o -name "*.conf" | xargs sed -i 's/\r//'

echo "Syncing to $TARGET_HOST:$REMOTE_DIR ..."
rsync -avz --progress \
    --exclude='.git' \
    --exclude='logs/*' \
    "$LOCAL_DIR/" "$TARGET_HOST:$REMOTE_DIR/"

echo "Setting permissions on remote..."
ssh "$TARGET_HOST" "find $REMOTE_DIR -name '*.sh' | xargs chmod +x"

echo "Done. To run:"
echo "  ssh $TARGET_HOST"
echo "  sudo bash $REMOTE_DIR/master.sh"
