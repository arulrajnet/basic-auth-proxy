Handle all incoming HTTP requests except those targeting endpoints starting with /auth/.
Check if the request has a valid session cookie using Gorilla Sessions and Securecookie.
If no session cookie exists or the session is invalid/expired, redirect the user to /auth/login with a 302 status code.
If a valid session is present, proxy the request to the upstream backend service, including the appropriate Basic Auth headers.

The middleware should:

Use github.com/gorilla/mux for routing.
Use github.com/gorilla/sessions with github.com/gorilla/securecookie for session management.
Validate the session by checking the session store for an active session.
Redirect to /auth/login if no valid session is found or the session is expired.
Proxy requests to the upstream service URL configured via github.com/spf13/viper (support both pflag and YAML configuration, with a fallback to a default upstream URL like http://backend-service:8080).
Add Basic Auth headers to the proxied request using credentials stored in the session.
Handle errors for upstream connection issues and return appropriate HTTP status codes (e.g., 502 for upstream errors).
Be compatible with Go's net/http package.


PS: The `/auth` is coming from the configuration.
