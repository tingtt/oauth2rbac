# Deploy with Docker Compose

## 1. OAuth2 Configuration and .env File

First, set up at least one OAuth2 provider.

- **Google Cloud**
  - [Create OAuth client ID](https://console.cloud.google.com/apis/credentials/oauthclient)

- **GitHub**
  - [Register a new OAuth application](https://github.com/settings/applications/new)

Encode the OAuth2 client credentials with base64 and store them in a `.env` file.

```sh
echo -n '<Your client ID>;<Your client secret>' | base64
```

Create a `.env` file with the following contents:

```env
JWT_SECRET=<base64-encoded JWT secret>
OAUTH2_GOOGLE=<base64-encoded OAuth2 client credential set>
OAUTH2_GITHUB=<base64-encoded OAuth2 client credential set>
```

## 2. Create `config.yaml`

Create a `config.yaml` file for configuring reverse proxies and access control lists (ACL).

```yaml
proxies:
  #! admin
  - external_url: "https://grafana.example.com/"
    target: "http://grafana:3000/"
  - external_url: "https://prometheus.example.com/"
    target: "http://prometheus:9090/"

  #! internal
  - external_url: "https://example.com/api/"
    target: "http://app:3000/"
  - external_url: "https://api.example.com/"
    target: "http://app:3000/"

  #! public
  - external_url: "https://example.com/"
    target: "http://web:80/"
  - external_url: "https://www.example.com/"
    target: "http://web:80/"

acl:
  "https://example.com":
    paths:
      "/":
        - methods: ["GET"]
          emails: ["-"] # public
  "https://www.example.com":
    paths:
      "/":
        - methods: ["GET"]
          emails: ["-"] # public
  "https://internal.example.com":
    paths:
      "/"
        - methods: ["*"]
          emails: ["*@example.com"]
  "https://grafana.example.com/":
    paths:
      "/"
        - methods: ["*"]
          emails: ["<your email>"]
  "https://prometheus.example.com/":
    paths:
      "/"
        - methods: ["*"]
          emails: ["<your email>"]
  "https://gallery.example.com/":
    paths:
      "/"
        - methods: ["*"]
          emails: ["<your email>"]
```

## 3. Create `compose.yaml`

Create a `compose.yaml` file to define services.

```yaml
services:
  oauth2rbac:
    image: tingtt/oauth2rbac:v1.0.0
    command: [
      "--port", "80",
      "--jwt-secret", "$(JWT_SECRET)",
      "-f", "/etc/oauth2rbac/config.yaml",
      "--oauth2-client", "github;$(OAUTH2_GITHUB)",
      "--oauth2-client", "google;$(OAUTH2_GOOGLE)",
    ]
    ports:
      - "80:80"
    environment:
      - JWT_SECRET=${JWT_SECRET}
      - OAUTH2_GOOGLE=${OAUTH2_GOOGLE}
      - OAUTH2_GITHUB=${OAUTH2_GITHUB}
    volumes:
      - ./config.yaml:/etc/oauth2rbac/config.yaml
    restart: always

  app:
    image: example.com/app:latest
    ports:
      - "3000":"3000"
  web:
    image: nginx:latest
    ports:
      - "80":"80"
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090":"9090"
  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000":"3000"
```

## 4. Setup TLS Termination

### Built-in TLS Termination

Provision certificates

```sh
$ mkdir -p tls/example.com/

# Get certificates...
#   (e.g. certbot, ca-certificate, etc.)

$ ls
tls.crt tls.key
```

Modify the `compose.yaml` to enable built-in TLS termination:

```diff
services:
  oauth2rbac:
    image: tingtt/oauth2rbac:v1.0.0
    command: [
-     "--port", "80",
+     "--port", "443",
      "--jwt-secret", "$(JWT_SECRET)",
      "-f", "/etc/oauth2rbac/config.yaml",
      "--oauth2-client", "github;$(OAUTH2_GITHUB)",
      "--oauth2-client", "google;$(OAUTH2_GOOGLE)",
+     "--tls-cert", "/etc/oauth2rbac/tls/example.com/tls.crt;/etc/oauth2rbac/tls/example.com/tls.key",
    ]
    ports:
-     - "80:80"
+     - "443:443"
    environment:
      - JWT_SECRET=${JWT_SECRET}
      - OAUTH2_GOOGLE=${OAUTH2_GOOGLE}
      - OAUTH2_GITHUB=${OAUTH2_GITHUB}
    volumes:
      - ./config.yaml:/etc/oauth2rbac/config.yaml
+     - ./tls:/etc/oauth2rbac/tls/example.com
    restart: always
```

Ensure the TLS certificate and key are stored in the `./tls` directory.
