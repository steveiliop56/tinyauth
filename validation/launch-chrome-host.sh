#!/bin/bash
# Launch Chrome from host (not in container)
# This script should be run on your host machine

set -e

echo "Launching Chrome for OIDC test setup..."

# Detect Chrome
if command -v google-chrome &> /dev/null; then
    CHROME_CMD="google-chrome"
elif command -v chromium-browser &> /dev/null; then
    CHROME_CMD="chromium-browser"
elif command -v chromium &> /dev/null; then
    CHROME_CMD="chromium"
elif [ -f "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]; then
    CHROME_CMD="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
else
    echo "Error: Chrome not found. Please install Google Chrome or Chromium."
    exit 1
fi

echo "Using: $CHROME_CMD"
echo "Opening: http://client.example.com/ (OIDC test client)"
echo ""

$CHROME_CMD \
    --host-resolver-rules="MAP auth.example.com 127.0.0.1, MAP client.example.com 127.0.0.1" \
    --disable-features=HttpsOnlyMode \
    --unsafely-treat-insecure-origin-as-secure=http://auth.example.com,http://client.example.com \
    --user-data-dir=/tmp/chrome-test-profile-$(date +%s) \
    --new-window \
    http://client.example.com/ \
    > /dev/null 2>&1 &

echo "Chrome launched!"
echo "OIDC test client: http://client.example.com/"
echo "Tinyauth: http://auth.example.com/"

