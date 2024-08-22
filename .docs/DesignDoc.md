# Design Doc: oauth2rbac

## Objective

`oauth2rbac` is a reverse proxy designed to manage both authentication and authorization. It leverages OAuth2 for Single Sign-On (SSO) and enforces Role-Based Access Control (RBAC) based on user email addresses. The system manages access to services through predefined rules, supporting email domains from Gmail and GitHub accounts.

## Goal and Non-Goal

### Goal

- **OAuth2 SSO**: Integrate Single Sign-On (SSO) using OAuth2 providers like Google and GitHub, focusing on email-based authentication.
- **RBAC Enforcement**: Manage access by controlling which URLs can be accessed by users based on their email domain or specific email addresses.
- **Simple Access Management**: Utilize a YAML file to define access control rules for different URLs, ensuring straightforward management.
- **Secure Proxying**: Ensure the safe forwarding of requests to internal services while enforcing access control based on RBAC policies.

### Non-Goal

- **Comprehensive Identity Management**: `oauth2rbac` is not intended to replace full identity management systems but serves as a focused reverse proxy solution.
- **Zero Trust Security**: It does not aim to provide zero-trust security for the applications it proxies.
- **Fine-Grained Permissions**: It will not manage detailed permissions beyond basic email and URL-based RBAC.

## High Level Structure

```sh
.
├── .docs/    # Documents
│   ├── deloy/
│   └── DesignDoc.md
├── cmd/      # Entrypoints
│   └── proxy/
├── internal/
│   ├── acl/
│   ├── oauth2/  # Handlers for OAuth2 providers (`google`, `github`, etc.)
│   ├── api/     # Web API server
│   │   ├── handler/
│   │   │   ├── reverse_proxy/
│   │   │   ├── oauth2/
│   │   │   └── util/    # Handler utilities (`cookie`, `url`, `log`, etc.)
│   │   └── middleware/
│   └── util/    # Basic utilities (`slices`, `tree`, `options`, etc.)
└── test/
    └── e2e/  # E2E test environments
```

## Open Issues

## References
