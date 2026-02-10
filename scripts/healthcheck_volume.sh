#!/bin/bash
# V56 Volume Health Check
# Verifies that /app/media is mounted and writable by the current user.

MOUNT_POINT="/app/media"
TEST_FILE="$MOUNT_POINT/.healthcheck_$(date +%s)"

echo "Starting V56 Volume Health Check..."

if [ ! -d "$MOUNT_POINT" ]; then
  echo "CRITICAL: Mount point $MOUNT_POINT does not exist!"
  exit 1
fi

echo "Attempting write to $TEST_FILE..."
if touch "$TEST_FILE"; then
  echo "SUCCESS: Volume is writable."
  rm "$TEST_FILE"
  exit 0
else
  echo "CRITICAL: Cannot write to $MOUNT_POINT. Check permissions or mount status."
  exit 1
fi
