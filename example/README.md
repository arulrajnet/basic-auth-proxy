# Example: Nagios with BasicAuth Proxy

This example demonstrates how to use **BasicAuth Proxy** to modernize the authentication experience for a legacy Nagios monitoring system. Instead of relying on HTTP Basic Authentication prompts, users will be presented with a branded login page while the proxy handles the Basic Auth communication with the backend Nagios service.

## Overview

The example stack includes:
- **BasicAuth Proxy** - Provides a modern login interface and session management
- **Nagios Legacy** - The upstream monitoring service that uses HTTP Basic Authentication

## Architecture

```
User Browser → BasicAuth Proxy (Port 80) → Nagios Legacy (Internal Port 80)
```

The proxy intercepts all requests, checks for valid sessions, and either:
1. Serves a login page for unauthenticated users
2. Forwards authenticated requests to Nagios with proper Basic Auth headers

## Prerequisites

- Docker and Docker Compose installed
- Git (to clone the repository if not already done)

## Quick Start

### 1. Navigate to the Example Directory

```bash
cd example/
```

### 2. Source Environment Variables

```bash
source .envrc
```

This loads the required environment variables for building the proxy:
- `GIT_COMMIT` - Current git commit hash
- `VERSION` - Version from git tags
- `TARGETPLATFORM` - Target platform for Docker build

### 3. Start the Stack

```bash
docker-compose up -d
```

This command will:
- Build the BasicAuth Proxy from the parent directory
- Pull and start the Nagios container
- Configure networking between the services

### 4. Verify Services are Running

```bash
docker-compose ps
```

You should see both services running:
```
NAME                 COMMAND                  SERVICE         STATUS    PORTS
example-nagios_legacy-1   "/usr/local/bin/star…"   nagios_legacy   running   0.0.0.0:32768->80/tcp
example-proxy-1           "basic-auth-proxy --…"   proxy           running   0.0.0.0:80->80/tcp
```

### 5. Access the Application

Open your browser and navigate to:
```
http://localhost/
```

You'll be redirected to a branded login page instead of seeing a browser Basic Auth popup.

### 6. Login Credentials

Use the default Nagios credentials:
- **Username**: `nagiosadmin`
- **Password**: `nagiosadmin`

After successful authentication, you'll be redirected to the Nagios dashboard and can navigate the monitoring interface normally.

## How It Works

1. **Initial Request**: When you visit `http://localhost/`, the proxy detects you don't have a valid session
2. **Login Redirect**: You're redirected to `/auth/login` where a branded login form is displayed
3. **Authentication**: When you submit credentials, the proxy validates them against Nagios using Basic Auth
4. **Session Creation**: On successful auth, a secure session cookie is set and you're redirected to your original destination
5. **Subsequent Requests**: The proxy automatically includes Basic Auth headers for all requests to Nagios

## Configuration Details

The proxy is configured with the following settings (see `docker-compose.yaml`):

- **Address**: `0.0.0.0` (listens on all interfaces)
- **Port**: `80`
- **Proxy Prefix**: `/auth/` (login/logout endpoints)
- **Upstream**: `http://nagios_legacy:80/` (internal Docker network)
- **Log Level**: `debug` (for development)

## Useful Commands

### View Logs
```bash
# All services
docker-compose logs -f

# Just the proxy
docker-compose logs -f proxy

# Just Nagios
docker-compose logs -f nagios_legacy
```

### Restart Services
```bash
# Restart everything
docker-compose restart

# Restart just the proxy (useful during development)
docker-compose restart proxy
```

### Rebuild the Proxy
```bash
# Rebuild and restart the proxy
docker-compose up -d --build proxy
```

### Stop the Stack
```bash
docker-compose down
```

### Clean Up (Remove Volumes)
```bash
docker-compose down -v
```

## Testing Different Scenarios

### Test Invalid Credentials
Try logging in with incorrect credentials to see the error handling.

### Test Session Persistence
After logging in successfully, close your browser and reopen it. You should still be logged in until the session expires.

### Test Direct Access
Try accessing `http://localhost/nagios/` directly - you should be redirected to the login page.

## Customization

You can customize the login page branding by modifying the templates in the `pkg/templates/` directory of the main project and rebuilding the proxy.

## Troubleshooting

### Port 80 Already in Use
If port 80 is already in use on your system, modify the `docker-compose.yaml` to use a different port:

```yaml
ports:
  - "8080:80"  # Use port 8080 instead
```

Then access the application at `http://localhost:8080/`

### Services Not Starting
Check the logs for any error messages:
```bash
docker-compose logs
```

### Cannot Access Nagios
Ensure both services are running and healthy:
```bash
docker-compose ps
docker-compose logs nagios_legacy
```

## Next Steps

After exploring this example, you can:
1. Deploy BasicAuth Proxy in front of your own legacy applications
2. Customize the branding and styling
3. Configure SSL/TLS for production use
4. Set up proper session management and security headers

For more configuration options and production deployment guidance, see the main project README.
