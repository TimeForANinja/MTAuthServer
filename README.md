# auth

Simple JWT authentication service against Active Directory.

## Configuration

The application is configured using environment variables. You can create a `.env` file from the provided `.env.example`.

### ENV parameters

| env variable             | Description                                                                                                               |
|--------------------------|---------------------------------------------------------------------------------------------------------------------------|
| MAS_AUTH_LDAP_SERVER1    | LDAP Server 1 (e.g., `ldaps://server:636`)                                                                                |
| MAS_AUTH_LDAP_SERVER2    | LDAP Server 2 (optional)                                                                                                  |
| MAS_AUTH_LDAP_TLSVERIFY1 | LDAP SSL Verify Server 1 (`true`/`false`)                                                                                 |
| MAS_AUTH_LDAP_TLSVERIFY2 | LDAP SSL Verify Server 2 (`true`/`false`)                                                                                 |
| MAS_AUTH_SEARCHBASE      | LDAP Searchbase (e.g., `OU=test,DC=example,DC=com`)                                                                       |
| MAS_AUTH_USERFILTER      | Userfilter, use `{}` for username (e.g., `(sAMAccountName={})`)                                                           |
| MAS_AUTH_GROUPFILTER     | Groupfilter, use `{}` for group name (e.g., `(&(objectClass=group)(member={}))`)                                          |
| MAS_AUTH_TOKEN_LIFETIME  | JWT Token lifetime in seconds (e.g., `3600`)                                                                              |
| MAS_AUTH_BINDDN          | LDAP BindDN of service user                                                                                               |
| MAS_AUTH_BINDPASSWORD    | LDAP BindDN Password of service user                                                                                      |
| MAS_AUTH_SECRETKEY       | Encryption Key for JWT Tokens                                                                                             |

## RUN demo environment

1. Copy `.env.example` to `.env` 
2. Modify `.env` with your settings.
3. Launch `docker compose up`

## Deployment on Kubernetes 

### deployment.yaml

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth
  namespace: nap
  labels:
    app: auth
spec:
  replicas: 3
  selector:
    matchLabels:
      app: auth
  template:
    metadata:
      labels:
        app: auth
    spec:
      containers:
      - name: auth
        image: your.repo.url/org/auth:v1.0.0
        ports:
        - containerPort: 4999
        env:
          - name: MAS_AUTH_LDAP_SERVER1
            value: "ldap://x.x.x.x:389"
          - name: MAS_AUTH_LDAP_SERVER2
            value: "ldap://x.x.x.x:389"
          - name: MAS_AUTH_LDAP_TLSVERIFY1
            value: "false"
          - name: MAS_AUTH_LDAP_TLSVERIFY2
            value: "false"
          - name: MAS_AUTH_SEARCHBASE
            value: "OU=test,DC=xxxxx,DC=xxxx,DC=airbusds,DC=corp"
          - name: MAS_AUTH_USERFILTER
            value: "(sAMAccountName={})"
          - name: MAS_AUTH_GROUPFILTER
            value: "(&(objectClass=group)(member={}))"
          - name: MAS_AUTH_TOKEN_LIFETIME
            value: "3600"

          - name: MAS_AUTH_BINDDN
            valueFrom:
              secretKeyRef:
                name: my-auth-secret
                key: MAS_AUTH_BINDDN
          - name: MAS_AUTH_BINDPASSWORD
            valueFrom:
              secretKeyRef:
                name: my-auth-secret
                key: MAS_AUTH_BINDPASSWORD
          - name: MAS_AUTH_SECRETKEY
            valueFrom:
              secretKeyRef:
                name: my-auth-secret
                key: MAS_AUTH_SECRETKEY

```


### ingress.yaml

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auth-ingress
  namespace: nap
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
    nginx.ingress.kubernetes.io/proxy-ssl-verify: "off"
    nginx.ingress.kubernetes.io/affinity: "cookie"
    nginx.ingress.kubernetes.io/session-cookie-name: "route"
    nginx.ingress.kubernetes.io/session-cookie-hash: "sha1"
    nginx.ingress.kubernetes.io/session-cookie-expire: "86400"
    nginx.ingress.kubernetes.io/session-cookie-max-age: "86400"
spec:
  tls:
  - hosts:
    - auth.xxx.xxx.airbusds.corp
    secretName: auth-tls
  rules:
  - host: auth.xxx.xxx.airbusds.corp
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: auth-service
            port:
              number: 443

```

### service.yaml

```yaml
apiVersion: v1
kind: Service
metadata:
  name: auth-service
  namespace: nas
spec:
  ports:
  - port: 443
    targetPort: 4999
  selector:
    app: auth
```

### secrets.yaml

Create a sealed secret with bitnami/sealedsecrets.

```yaml
---
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  creationTimestamp: null
  name: my-auth-secret
  namespace: nap
spec:
  encryptedData:
    MAS_AUTH_BINDDN: xxxxx
    MAS_AUTH_BINDPASSWORD: xxxxx
    MAS_AUTH_SECRETKEY: xxxxx
  template:
    metadata:
      creationTimestamp: null
      name: my-auth-secret
      namespace: nap
    type: Opaque
```