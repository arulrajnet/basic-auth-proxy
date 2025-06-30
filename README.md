# BasicAuth Proxy

**BasicAuth-Proxy** is a brandable, lightweight reverse proxy designed to modernize and secure legacy applications that rely on HTTP Basic Authentication. By introducing an authentication layer that issues session-based credentials, the proxy mitigates many of the inherent risks and usability challenges associated with exposing Basic Auth directly to end users.

## Key Features:

* Brandable Login Screen – Customize the UI to match your brand.
* Session Management – Convert Basic Auth into session-based authentication.
* Secure Reverse Proxy – Acts as a gateway to upstream services with Basic Auth.
* Improved User Experience – Eliminates the need for users to enter credentials repeatedly.
* Seamless Integration – Drop-in replacement for services requiring Basic Auth.

Ideal for teams looking to modernize authentication without modifying upstream applications.

## Architecture

![basic-auth-proxy.drawio.png](basic-auth-proxy.drawio.png)

The following diagram illustrates how BasicAuth Proxy works:

```mermaid
sequenceDiagram
    actor User
    participant Login as Login Screen
    participant Proxy as BasicAuth Proxy
    participant Backend as Backend Service<br>(with Basic Auth)

    Note over User, Backend: First Access (No Session)
    User->>Proxy: 1. Access Service
    alt No Session Cookie
        Proxy->>Login: 2a. Redirect to Login Screen
        Login->>User: 2b. Display Login Form
        User->>Login: 3a. Enter Username/Password
        Login->>Proxy: 3b. Submit Credentials
        Proxy->>Backend: 4. Validate Credentials<br>(Basic Auth Header)
        Backend->>Proxy: 5. Authentication Response
        alt Auth Success
            Proxy->>User: 6a. Set Session Cookie & Redirect
        else Auth Failure
            Proxy->>Login: 6b. Show Error Message
            Login->>User: 6c. Display Error
        end
    end

    Note over User, Backend: Subsequent Requests (With Session)
    User->>Proxy: 7. Request with Session Cookie
    Proxy->>Backend: 8. Forward Request with Basic Auth
    Backend->>Proxy: 9. Response
    Proxy->>User: 10. Forward Response

    Note over User, Backend: Session Expiry
    User->>Proxy: Request with Expired Session
    Proxy->>Login: Redirect to Login Screen
```

## Usage


## Roadmap

- [ ] Support for SSL/TLS encryption
- [ ] Support for Let's Encrypt automatic certificate management
- [ ] Support for multiple upstream services
- [ ] Support for configurable cookie flags (secure, httpOnly, sameSite)
- [ ] Run behind another reverse proxy (X-Forwarded-For support)



## Author

<p align="center">
  <a href="https://x.com/arulrajnet">
    <img src="https://github.com/arulrajnet.png?size=100" alt="Arulraj V" width="100" height="100" style="border-radius: 50%;" class="avatar-user">
  </a>
  <br>
  <strong>Arul</strong>
  <br>
  <a href="https://x.com/arulrajnet">
    <img src="https://img.shields.io/badge/Follow-%40arulrajnet-1DA1F2?style=for-the-badge&logo=x&logoColor=white" alt="Follow @arulrajnet on X">
  </a>
  <a href="https://github.com/arulrajnet">
    <img src="https://img.shields.io/badge/GitHub-arulrajnet-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub @arulrajnet">
  </a>
  <a href="https://linkedin.com/in/arulrajnet">
    <img src="https://custom-icon-badges.demolab.com/badge/LinkedIn-arulrajnet-0A66C2?style=for-the-badge&logo=linkedin-white&logoColor=white" alt="LinkedIn @arulrajnet">
  </a>
</p>
