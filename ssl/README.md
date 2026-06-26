# SSL Certificates

Place your production SSL certificates here:
- `nginx.crt` (Certificate)
- `nginx.key` (Private Key)

For local development or testing, you can generate self-signed certificates using openssl:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout nginx.key -out nginx.crt -subj "/CN=localhost"
```
