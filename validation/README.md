# OIDC Validation Setup

This directory contains a docker-compose setup for testing tinyauth's OIDC provider functionality with a minimal test client.

## Setup

1. **Build the OIDC test client image:**
   ```bash
   docker build -t oidc-whoami-test:latest .
   ```

2. **Start the services:**
   ```bash
   docker compose up --build
   ```

## Services

### nginx
- **Purpose:** Reverse proxy for `auth.example.com` → tinyauth
- **Ports:** 80 (exposed to host)
- **Access:** http://auth.example.com/ (via nginx on port 80)

### dns
- **Purpose:** DNS server (dnsmasq) that resolves `auth.example.com` to the tinyauth container
- **Configuration:** Resolves `auth.example.com` to the `tinyauth` container IP (172.28.0.20) within the Docker network
- **Ports:** 53 (UDP/TCP) - not exposed to host (only for container-to-container communication)

### tinyauth
- **URL:** http://auth.example.com/ (via nginx)
- **Credentials:** `user` / `pass`
- **OIDC Discovery:** http://auth.example.com/api/.well-known/openid-configuration
- **OIDC Client ID:** `testclient`
- **OIDC Client Secret:** `test-secret-123`
- **Ports:** Not exposed to host (accessed via nginx on port 80)

### oidc-whoami
- **Callback URL:** http://localhost:8765/callback
- **Purpose:** Minimal OIDC test client that validates the OIDC flow
- **Ports:** 8765 (exposed to host)

## Quick Start

1. **Start all services:**
   ```bash
   docker compose up --build -d
   ```

2. **Launch Chrome with host-resolver-rules:**
   ```bash
   ./launch-chrome-host.sh
   ```
   
   Or manually:
   ```bash
   google-chrome \
     --host-resolver-rules="MAP auth.example.com 127.0.0.1" \
     --disable-features=HttpsOnlyMode \
     --unsafely-treat-insecure-origin-as-secure=http://auth.example.com \
     --user-data-dir=/tmp/chrome-test-profile \
     http://auth.example.com/
   ```
   
   **Note:** The `--user-data-dir` flag uses a temporary profile to avoid HSTS (HTTP Strict Transport Security) issues that might force HTTPS redirects.

3. **Access tinyauth:** http://auth.example.com/
   - Login with: `user` / `pass`

4. **Test OIDC flow:**
   ```bash
   # Get authorization URL from oidc-whoami logs
   docker compose logs oidc-whoami | grep "Authorization URL"
   # Open that URL in Chrome (already configured with host-resolver-rules)
   ```

## Connecting from Chrome/Browser

Since the DNS server is only accessible within the Docker network, you have several options to access `auth.example.com` from your browser:

### Option 1: Use /etc/hosts (Simplest)

Add this line to your `/etc/hosts` file (or `C:\Windows\System32\drivers\etc\hosts` on Windows):

```
127.0.0.1 auth.example.com
```

Then access: http://auth.example.com/

**To edit /etc/hosts on Linux/Mac:**
```bash
sudo nano /etc/hosts
# Add: 127.0.0.1 auth.example.com
```

**To edit hosts on Windows:**
1. Open Notepad as Administrator
2. Open `C:\Windows\System32\drivers\etc\hosts`
3. Add: `127.0.0.1 auth.example.com`

### Option 2: Use Chrome's `--host-resolver-rules` (Chrome-specific, No System Changes)

Chrome has a command-line flag that lets you map hostnames directly, bypassing DNS entirely. This is perfect for testing without modifying system settings.

**To use it:**

1. **Make sure services are running:**
   ```bash
   docker compose up -d
   ```

2. **Launch Chrome with the host resolver rule:**

   **Linux:**
   ```bash
   google-chrome --host-resolver-rules="MAP auth.example.com 127.0.0.1"
   ```
   
   **Mac:**
   ```bash
   /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
     --host-resolver-rules="MAP auth.example.com 127.0.0.1"
   ```
   
   **Windows:**
   ```cmd
   "C:\Program Files\Google\ Chrome\Application\chrome.exe" --host-resolver-rules="MAP auth.example.com 127.0.0.1"
   ```

3. **Or modify Chrome's shortcut:**
   - Right-click Chrome shortcut → Properties
   - In "Target" field, append: ` --host-resolver-rules="MAP auth.example.com 127.0.0.1"`
   - Click OK

4. **Access:** http://auth.example.com/

**Note:** This only affects Chrome, not other applications. The DNS server on port 5353 isn't needed for this approach.

### Option 3: Use System DNS (All Applications)

If you want to use the DNS server on port 5353 for all applications (not just Chrome), configure your system DNS:

**Linux (with systemd-resolved):**
```bash
# Configure systemd-resolved to use our DNS
sudo resolvectl dns lo 127.0.0.1:5353
```

**Linux (without systemd-resolved):**
```bash
# Edit /etc/resolv.conf
sudo nano /etc/resolv.conf
# Add: nameserver 127.0.0.1
# Note: This won't work with port 5353, you'd need port 53
```

**Note:** Most systems expect DNS on port 53. To use port 5353, you'd need a DNS proxy or configure Chrome specifically (see Option 2 above).

## Testing

1. Start the services with `docker compose up --build -d`
2. Launch Chrome: `./launch-chrome-host.sh` (or use `--host-resolver-rules` manually)
3. Navigate to: http://auth.example.com/
4. Login with `user` / `pass`
5. Test the OIDC flow by accessing the discovery endpoint: http://auth.example.com/api/.well-known/openid-configuration

## Configuration

The tinyauth configuration is in `config.yaml`:
- OIDC is enabled
- Single user: `user` with password `pass`
- OIDC client `testclient` is configured with redirect URI `http://localhost:8765/callback`
- App URL and OIDC issuer: `http://auth.example.com` (via nginx on port 80)

## Notes

- All containers are on a custom Docker network (`tinyauth-network`) with a DNS server for domain resolution
- The DNS server resolves `auth.example.com` to the tinyauth container within the network
- The redirect URI must match exactly what's configured in tinyauth
- Data is persisted in the `./data` directory
- The domain `auth.example.com` is used to satisfy cookie domain validation requirements (needs at least 3 domain parts and not in public suffix list)
