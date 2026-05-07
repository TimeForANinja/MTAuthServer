# MTAuthServer

Simple JWT authentication service against Active Directory / LDAP, built with APIFlask.

## Features

- LDAP / Active Directory authentication.
- Recursive group lookup (nested groups).
- JWT token generation with user groups and attributes.
- Token introspection endpoint.
- OpenAPI (Swagger) documentation.
- High availability with LDAP server pooling.

## Configuration

The application is configured using environment variables. You can create a `.env` file from the provided `.env.example`.
All variables must be prefixed with `MAS_AUTH_`.

### Environment Variables

| Env Variable | Description | Default |
|--------------|-------------|---------|
| `MAS_AUTH_PORT` | Port the application listens on | `8080` |
| `MAS_AUTH_LDAP_SERVERS` | Comma-separated list of LDAP servers (e.g., `ldaps://server1:636,ldap://server2`) | (Required) |
| `MAS_AUTH_LDAP_TLS_VERIFY` | Whether to verify LDAP SSL certificates (`true`/`false`) | `false` |
| `MAS_AUTH_BINDDN` | LDAP Bind DN for the service account | (Required) |
| `MAS_AUTH_BINDPASSWORD` | LDAP Bind Password for the service account | (Required) |
| `MAS_AUTH_SEARCHBASE` | LDAP Search Base (e.g., `OU=Users,DC=example,DC=com`) | (Required) |
| `MAS_AUTH_USERFILTER` | LDAP filter for finding users, `{}` is replaced by username | `(sAMAccountName={})` |
| `MAS_AUTH_GROUPFILTER` | LDAP filter for finding groups | `(&(objectClass=group)(member={}))` |
| `MAS_AUTH_SECRETKEY` | Secret key used for signing JWT tokens | (Randomly generated if not set) |
| `MAS_AUTH_TOKEN_LIFETIME` | JWT Token lifetime in seconds | `3600` |
| `MAS_AUTH_PROXY_FIX` | Enable Werkzeug ProxyFix for running behind a reverse proxy | `true` |
| `MAS_AUTH_DEBUG` | Enable debug mode | `false` |

## API Documentation

Once the application is running, you can access the interactive API documentation at:
- Swagger UI: `http://localhost:8080/docs`

## Run with Docker Compose

1. Copy `.env.example` to `.env`
2. Modify `.env` with your settings.
3. Launch:
   ```bash
   docker compose up -d
   ```

## Deployment on Kubernetes

### deployment.yaml

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mtauthserver
  labels:
    app: mtauthserver
spec:
  replicas: 2
  selector:
    matchLabels:
      app: mtauthserver
  template:
    metadata:
      labels:
        app: mtauthserver
    spec:
      containers:
      - name: mtauthserver
        image: your.repo.url/mtauthserver:latest
        ports:
        - containerPort: 8080
        env:
          - name: MAS_AUTH_LDAP_SERVERS
            value: "ldaps://dc1.example.com:636,ldaps://dc2.example.com:636"
          - name: MAS_AUTH_LDAP_TLS_VERIFY
            value: "true"
          - name: MAS_AUTH_SEARCHBASE
            value: "DC=example,DC=com"
          - name: MAS_AUTH_BINDDN
            valueFrom:
              secretKeyRef:
                name: mtauthserver-secrets
                key: BINDDN
          - name: MAS_AUTH_BINDPASSWORD
            valueFrom:
              secretKeyRef:
                name: mtauthserver-secrets
                key: BINDPASSWORD
          - name: MAS_AUTH_SECRETKEY
            valueFrom:
              secretKeyRef:
                name: mtauthserver-secrets
                key: SECRETKEY
```

### service.yaml

```yaml
apiVersion: v1
kind: Service
metadata:
  name: mtauthserver
spec:
  ports:
  - port: 80
    targetPort: 8080
  selector:
    app: mtauthserver
```
