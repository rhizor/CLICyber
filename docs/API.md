# CLI Cyber - API REST

## Introducción

CLI Cyber incluye un servidor REST API basado en FastAPI que permite acceder programáticamente a todas las funcionalidades de la CLI.

## Iniciar Servidor

```bash
# Iniciar servidor
python3 -m cybercli.cli api --host 0.0.0.0 --port 8000

# Con auto-reload
python3 -m cybercli.cli api --reload

# Puerto específico
python3 -m cybercli.cli api --port 9000
```

## Endpoints

### Health Check

```http
GET /health
```

Respuesta:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "timestamp": "2024-01-01T00:00:00Z",
  "services": {
    "api": "up",
    "scanner": "up"
  }
}
```

### Escaneo de Red

```http
POST /scan/network
```

Body:
```json
{
  "target": "192.168.1.0/24",
  "top_ports": 100
}
```

Respuesta:
```json
{
  "status": "completed",
  "target": "192.168.1.0/24",
  "timestamp": "2024-01-01T00:00:00Z",
  "results": {
    "hosts": {
      "192.168.1.1": [22, 80, 443],
      "192.168.1.10": [3389]
    }
  }
}
```

### Escaneo de Malware

```http
POST /scan/malware
```

Body:
```json
{
  "path": "/var/www",
  "recursive": true
}
```

### Threat Intelligence

```http
POST /threatintel
```

Body:
```json
{
  "indicator": "8.8.8.8",
  "sources": ["shodan", "abuseipdb"]
}
```

### Query CVE

```http
POST /cve/query
```

Body (buscar por ID):
```json
{
  "cve_id": "CVE-2024-0001"
}
```

Body (buscar por keyword):
```json
{
  "keyword": "nginx"
}
```

Body (buscar por producto):
```json
{
  "product": "openssl",
  "vendor": "openssl"
}
```

Body (recientes):
```json
{
  "days": 7
}
```

### Escanear Contenedores

```http
POST /container/scan
```

Body:
```json
{
  "target": "docker"
}
```

### File Integrity

```http
POST /fim
```

Crear baseline:
```json
{
  "action": "create-baseline",
  "paths": ["/etc"]
}
```

Verificar integridad:
```json
{
  "action": "check",
  "paths": ["/etc"]
}
```

### Compliance

```http
POST /compliance
```

Body:
```json
{
  "controls": ["A.5.1", "A.6.1"]
}
```

### Generar Reporte

```http
POST /report
```

Body:
```json
{
  "report_type": "technical",
  "format": "json",
  "include_ai": false
}
```

### Historial de Escaneos

```http
GET /scan/history?limit=50
```

## Ejemplo de Uso

### Python

```python
import requests

base_url = "http://localhost:8000"

# Health check
response = requests.get(f"{base_url}/health")
print(response.json())

# Network scan
response = requests.post(f"{base_url}/scan/network", json={
    "target": "192.168.1.0/24",
    "top_ports": 100
})
print(response.json())

# Threat intel
response = requests.post(f"{base_url}/threatintel", json={
    "indicator": "8.8.8.8",
    "sources": ["shodan"]
})
print(response.json())
```

### cURL

```bash
# Health check
curl http://localhost:8000/health

# Network scan
curl -X POST http://localhost:8000/scan/network \
  -H "Content-Type: application/json" \
  -d '{"target": "192.168.1.0/24", "top_ports": 100}'

# Threat intel
curl -X POST http://localhost:8000/threatintel \
  -H "Content-Type: application/json" \
  -d '{"indicator": "8.8.8.8", "sources": ["shodan"]}'
```

### JavaScript

```javascript
const baseUrl = 'http://localhost:8000';

// Health check
fetch(`${baseUrl}/health`)
  .then(res => res.json())
  .then(data => console.log(data));

// Network scan
fetch(`${baseUrl}/scan/network`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    target: '192.168.1.0/24',
    top_ports: 100
  })
})
  .then(res => res.json())
  .then(data => console.log(data));
```

## Documentación Interactiva

Cuando el servidor está corriendo, la documentación interactiva está disponible en:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Autenticación

Por defecto, la API no requiere autenticación. Para producción, se recomienda configurar autenticación.

## Rate Limiting

Por defecto, no hay rate limiting. Para producción, configurar con un proxy como nginx.
