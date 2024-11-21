# oauth2rbac

It's a reverse proxy that performs RBAC (Role Based Access Control) with SSO using OAuth2.  
It provides access control with email addresses tied to Gmail and GitHub accounts.

## Usage

### Running with Docker Compose

Refer to the documentation in [Docker Compose Deployment](.docs/deploy/docker/README.md) for instructions on how to deploy using Docker Compose.

### Running on Kubernetes

Refer to the documentation in [Kubernetes Deployment](.docs/deploy/k8s/README.md) for instructions on how to deploy on Kubernetes.


## Configuration

The reverse proxy is configured using a YAML file.

Below is an example of the configuration format:

```yaml
proxies:
  - external_url: "http://www.example.com/"
    target: "http://www:80/"
  - external_url: "http://www.example.com/blog/"
    target: "http://blog:80/"                    # cut the base url from request path with trailing slash "target"
                                                 #   "http://www.example.com/blog/1" proxy to "http:/blog:80/1"
  - external_url: "http://docs.example.com/"
    target: "http://docs:80/"
  - external_url: "http://admin.example.com/"
    target: "http://admin:80/"
    set_headers:
      Remote-User: ["tingtt"]                    # MIME header key will be normalized
                                                 #   "CUSTOM-HEADER" canonicalize to "Custom-Header"
acl:
  "-":                             # public
    - external_url: "http://www.example.com/"
      methods: ["GET"]
  "*":                             # allow all signed-in user
    - external_url: "http://docs.example.com/"
      methods: ["GET"]
  "*@example.com":                 # allow users with a specific domain
    - external_url: "http://docs.example.com/"
      methods: ["*"]
  "admin@example.com":             # allow specified email user
    - external_url: "http://admin.example.com/"
      methods: ["GET"]
```

### Proxies Section

- **external_url**: The external URL that the proxy will listen to.
- **target**: The internal target URL that the request will be forwarded to.
- **set_headers** (optional): Additional headers that should be set when proxying the request. Header keys will be normalized.

### ACL Section

#### Email

- **"-"**: Public access. No authentication required.
- **"*"**: Allows access to all authenticated users.
- **"*@example.com"**: Allows access to all users with a specific domain.

#### Allowed request

- **external_url**: The external URL allow.
- **mothods**: List of methods. (The wildcard “*” will allow all methods.)
