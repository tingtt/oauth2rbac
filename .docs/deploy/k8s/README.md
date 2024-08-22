# Deploy to Kubernetes

## Create manifests

### 1. `secret.yaml`

Set up at least one OAuth2 provider.

- **Google Cloud**
  - [Create OAuth client ID](https://console.cloud.google.com/apis/credentials/oauthclient)

- **GitHub**
  - [Register a new OAuth application](https://github.com/settings/applications/new)

And encode oauth2 client credential set with base64.

```sh
echo -n '<Your client ID>;<Yout client secret>' | base64
```

```yaml
# https://kubernetes.io/docs/concepts/configuration/secret/
apiVersion: v1
kind: Secret
metadata:
  name: secret
type: Opaque
data:
  jwt_secret: <base64-encoded jwt secert>
  oauth2_google: <base64-encoded oauth2 client credential set>
  oauth2_github: <base64-encoded oauth2 client credential set>
```

### 2. `config.yaml`

```yaml
# https://kubernetes.io/docs/concepts/configuration/configmap/
kind: ConfigMap
apiVersion: v1
metadata:
  name: oauth2rbac
data:
  oauth2rbac.yml: |
    proxies:
      #! admin
      - external_url: "https://argocd.example.com/"
        target: "https://argocd-server.argocd.svc.cluster.local:80/"
      - external_url: "https://grafana.example.com/"
        target: "http://grafana.monitoring-grafana.svc.cluster.local:3000/"
      - external_url: "https://prometheus.example.com/k8s"
        target: "http://prometheus-k8s.monitoring.svc.cluster.local:9090/"
      - external_url: "https://prometheus.example.com/virtualization"
        target: "http://prometheus.monitoring-virtualization.svc.cluster.local:9090/"
      - external_url: "https://prometheus.example.com/synthetics"
        target: "http://prometheus.monitoring-synthetics.svc.cluster.local:9090/"

      #! internal
      - external_url: "https://internal.example.com/"
        target: "http://app.internal.svc.cluster.local:80/"

      #! public
      - external_url: "https://example.com/"
        target: "http://homepage.www.svc.cluster.local:3000/"
      - external_url: "https://www.example.com/"
        target: "http://homepage.www.svc.cluster.local:3000/"

    acl:
      "-": #! public
        - "https://example.com/"
        - "https://www.example.com/"
        - "https://argocd.example.com/healthz"
        - "https://grafana.example.com/api/health"
      "*@example.com":
        - "https://internal.example.com/"
      "<your email>":
        - "https://argocd.example.com/"
        - "https://grafana.example.com/"
        - "https://prometheus.example.com/"
```

### 3. `oauth2rbac.yaml` (Deployment / Service)

The number of resources and replicas to be allocated should be adjusted to meet infrastructure requirements.

```yaml
# https://kubernetes.io/docs/concepts/workloads/controllers/deployment/
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oauth2rbac
  labels:
    app: oauth2rbac
spec:
  selector:
    matchLabels:
      app: oauth2rbac
  replicas: 1
  template:
    metadata:
      labels:
        app: oauth2rbac
    spec:
      containers:
        - name: oauth2rbac
          image: tingtt/oauth2rbac:v0.5.0
          imagePullPolicy: IfNotPresent
          resources:
            limits:
              cpu: 140m
              memory: 100Mi
            requests:
              cpu: 100m
              memory: 100Mi
          livenessProbe:
            tcpSocket:
              port: 80
            initialDelaySeconds: 5
            timeoutSeconds: 5
            successThreshold: 1
            failureThreshold: 3
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /healthz
              port: 80
            initialDelaySeconds: 5
            timeoutSeconds: 2
            successThreshold: 1
            failureThreshold: 3
            periodSeconds: 10
          ports:
            - containerPort: 80
              name: http
          env:
            - name: JWT_SECRET
              valueFrom:
                secretKeyRef:
                  name: secret
                  key: jwt_secret
            - name: OAUTH2_GOOGLE
              valueFrom:
                secretKeyRef:
                  name: secret
                  key: oauth2_google
            - name: OAUTH2_GITHUB
              valueFrom:
                secretKeyRef:
                  name: secret
                  key: oauth2_github
          args:
            [
              "--port", "80",
              "--jwt-secret", "$(JWT_SECRET)",
              "-f", "/etc/oauth2rbac/config.yml",
              "--oauth2-client", "github;$(OAUTH2_GITHUB)",
              "--oauth2-client", "google;$(OAUTH2_GOOGLE)",
            ]
          volumeMounts:
            - name: oauth2rbac-config
              subPath: oauth2rbac.yml
              mountPath: /etc/oauth2rbac/config.yml
      volumes:
        - name: oauth2rbac-config
          configMap:
            name: oauth2rbac
            items:
              - key: oauth2rbac.yml
                path: oauth2rbac.yml
      restartPolicy: Always
---
kind: Service
apiVersion: v1
metadata:
  name: oauth2rbac
spec:
  type: LoadBalancer
  loadBalancerIP: 192.168.0.253
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8/0
      name: http
```

### 4. `networkPolicy.yaml` (optional / if you needed)

Create a NetworkPolicy if needed.
For example, if you are reverse proxying Grafana and have set a NetworkPolicy for Grafana, add the namespace where oauth2rbac is deployed to the `spec.ingress.namespaceSelector`.

```diff_yaml
  apiVersion: networking.k8s.io/v1
  kind: NetworkPolicy
  metadata:
    labels:
      app.kubernetes.io/component: grafana
      app.kubernetes.io/name: grafana
      app.kubernetes.io/part-of: kube-prometheus
      app.kubernetes.io/version: 10.2.3
    name: grafana
  spec:
    egress:
      - {} # allow all out-bound
    ingress:
      - from:
          - podSelector:
              matchLabels:
                app.kubernetes.io/name: prometheus
          - namespaceSelector:
              matchLabels:
+               kubernetes.io/metadata.name: <Your NS name that deployed oauth2rbac> # allow in-bound from oauth2rbac
        ports:
          - port: 3000
            protocol: TCP
    podSelector:
      matchLabels:
        app.kubernetes.io/component: grafana
        app.kubernetes.io/name: grafana
        app.kubernetes.io/part-of: kube-prometheus
    policyTypes:
      - Egress
      - Ingress
```

### Setup TLS termination

#### With ingress-nginx

[TLS termination - Ingress-Nginx Controller](https://kubernetes.github.io/ingress-nginx/examples/tls-termination/)

#### Built-in TLS termination

Change deployment and service.

```diff
  # https://kubernetes.io/docs/concepts/workloads/controllers/deployment/
  apiVersion: apps/v1
  kind: Deployment
  metadata:
    name: oauth2rbac
    labels:
      app: oauth2rbac
  spec:
    selector:
      matchLabels:
        app: oauth2rbac
    replicas: 1
    template:
      metadata:
        labels:
          app: oauth2rbac
      spec:
        containers:
          - name: oauth2rbac
            image: tingtt/oauth2rbac:v0.5.0
            # ...other configuration omitted...
            args:
              [
-               "--port", "80",
+               "--port", "443",
                "--jwt-secret", "$(JWT_SECRET)",
                "-f", "/etc/oauth2rbac/config.yml",
                "--oauth2-client", "github;$(OAUTH2_GITHUB)",
                "--oauth2-client", "google;$(OAUTH2_GOOGLE)",
+               "--tls-cert", "/etc/oauth2rbac/tls/example.com/tls.crt;/etc/oauth2rbac/tls/example.com/tls.key",
              ]
            volumeMounts:
              - name: oauth2rbac-config
                subPath: oauth2rbac.yml
                mountPath: /etc/oauth2rbac/config.yml
+             - name: tls-example-com
+               mountPath: /etc/oauth2rbac/tls/example.com
        volumes:
          - name: oauth2rbac-config
            configMap:
              name: oauth2rbac
              items:
                - key: oauth2rbac.yml
                  path: oauth2rbac.yml
+         - name: tls-example-com
+           secret:
+             secretName: tls-example.com
        restartPolicy: Always
  ---
  kind: Service
  apiVersion: v1
  metadata:
    name: oauth2rbac
  spec:
    type: LoadBalancer
    loadBalancerIP: 192.168.0.253
    ports:
      - protocol: TCP
-       port: 80
-       targetPort: 8/0
-       name: http
+       port: 443
+       targetPort: 44/3
+       name: https
```

## Apply manifests

```sh
kubectl apply \
  -f secret.yaml \
  -f config.yaml \
  -f oauth2rbac.yaml \
  -f networkPolicy.yaml
```
