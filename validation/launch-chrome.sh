#!/bin/bash
set -e

echo "=========================================="
echo "Chrome Launcher for OIDC Test Setup"
echo "=========================================="

# Wait for nginx to be ready
echo "Waiting for nginx to be ready..."
for i in {1..30}; do
    if curl -s http://127.0.0.1/ > /dev/null 2>&1; then
        echo "✓ Nginx is ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "✗ Nginx not ready after 30 seconds"
        exit 1
    fi
    sleep 1
done

# Try to find Chrome on the host system
# Since we're in a container, we need to check common locations
CHROME_PATHS=(
    "/usr/bin/google-chrome"
    "/usr/bin/google-chrome-stable"
    "/usr/bin/chromium-browser"
    "/usr/bin/chromium"
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
)

CHROME_CMD=""
for path in "${CHROME_PATHS[@]}"; do
    if [ -f "$path" ] || command -v "$(basename "$path")" &> /dev/null; then
        CHROME_CMD="$(basename "$path")"
        break
    fi
done

if [ -z "$CHROME_CMD" ]; then
    echo ""
    echo "Chrome not found in container. This is expected."
    echo "Please launch Chrome manually on your host with:"
    echo ""
    echo '  google-chrome --host-resolver-rules="MAP auth.example.com 127.0.0.1" http://auth.example.com/'
    echo ""
    echo "Or use the launch script on your host:"
    echo "  ./launch-chrome.sh"
    echo ""
    exit 0
fi

echo "Found Chrome: $CHROME_CMD"
echo "Launching Chrome with host-resolver-rules..."
echo ""

$CHROME_CMD \
    --host-resolver-rules="MAP auth.example.com 127.0.0.1" \
    --new-window \
    http://auth.example.com/ \
    > /dev/null 2>&1 &

echo "✓ Chrome launched!"
echo ""
echo "Access tinyauth at: http://auth.example.com/"
echo "OIDC test client callback: http://127.0.0.1:8765/callback"
echo ""

