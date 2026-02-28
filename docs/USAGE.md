# CLI Cyber - Guía de Uso

## Comandos Básicos

### Ayuda

```bash
# Ayuda general
python3 -m cybercli --help

# Ayuda de subcomandos
python3 -m cybercli scan --help
python3 -m cybercli blue --help
python3 -m cybercli compliance --help
```

## Escaneo de Red

### Escaneo Básico

```bash
# Escaneo simple
python3 -m cybercli scan network 192.168.1.0/24

# Escaneo con puertos específicos
python3 -m cybercli scan network 192.168.1.0/24 --top-ports 100

# Escaneo detallado
python3 -m cybercli scan network 192.168.1.0/24 --verbose
```

### Perfiles de Escaneo

```bash
# Crear perfil
python3 -m cybercli scan save-profile web --ports 80,443,8080 --description "Puertos web"

# Listar perfiles
python3 -m cybercli scan list-profiles

# Usar perfil
python3 -m cybercli scan run-profile web 192.168.1.0/24

# Eliminar perfil
python3 -m cybercli scan delete-profile web
```

### Programación de Escaneos

```bash
# Agregar escaneo programado
python3 -m cybercli schedule add daily-scan 192.168.1.0/24 --cron "0 0 * * *"

# Listar escaneos
python3 -m cybercli schedule list

# Eliminar escaneo
python3 -m cybercli schedule remove daily-scan
```

## Escaneo de Malware

```bash
# Escanear directorio
python3 -m cybercli scan malware /var/www

# Con base de datos de firmas
python3 -m cybercli scan malware /path --signature-db firmas.json

# Escanear sin recursion
python3 -m cybercli scan malware /path --no-recurse
```

## Hardening del Sistema

```bash
# Verificación de hardening
python3 -m cybercli scan hardening

# Ver recomendaciones detalladas
python3 -m cybercli scan hardening --detailed
```

## Blue Team

### Análisis de Vulnerabilidades

```bash
# Escanear vulnerabilidades
python3 -m cybercli blue vuln-scan

# Escanear con puertos específicos
python3 -m cybercli blue vuln-scan --ports 22,80,443
```

### Análisis de Logs

```bash
# Análisis de logs de autenticación
python3 -m cybercli blue log-analysis /var/log/auth.log

# Análisis con umbrales
python3 -m cybercli blue log-analysis /var/log/auth.log --threshold 5
```

### Análisis de Autenticación

```bash
# Detectar logins fuera de horario
python3 -m cybercli blue auth-analysis /var/log/auth.log --start-hour 22 --end-hour 6

# Análisis completo
python3 -m cybercli blue auth-analysis /var/log/auth.log --start-hour 0 --end-hour 6
```

## Red Team

### Laboratorios CTF

```bash
# Crear laboratorio
python3 -m cybercli ctf create mylab --challenges 5

# Incluir desafío web
python3 -m cybercli ctf create mylab --challenges 3 --web-challenge

# Listar laboratorios
python3 -m cybercli ctf list

# Destruir laboratorio
python3 -m cybercli ctf destroy mylab --force
```

### Explotación

```bash
# Explotar laboratorio
python3 -m cybercli red exploit-lab mylab
```

## Threat Intelligence

```bash
# Consultar IP
python3 -m cybercli intel ip 8.8.8.8

# Consultar dominio
python3 -m cybercli intel domain example.com

# Consultar hash
python3 -m cybercli intel hash abc123...
```

## CVE Monitoring

```bash
# Buscar CVE específico
python3 -m cybercli.cli cve search CVE-2024-0001

# Ver CVEs recientes
python3 -m cybercli.cli cve recent --days 7

# Buscar por producto
python3 -m cybercli.cli cve product nginx --vendor apache
```

## Contenedores

```bash
# Escanear Docker
python3 -m cybercli.cli container docker

# Escanear Kubernetes
python3 -m cybercli.cli container kubernetes
```

## File Integrity Monitoring

```bash
# Crear baseline
python3 -m cybercli.cli fim create-baseline /etc --recursive

# Verificar integridad
python3 -m cybercli.cli fim check

# Monitoreo continuo
python3 -m cybercli.cli fim monitor /var/www --interval 60

# Listar baseline
python3 -m cybercli.cli fim list
```

## SIEM

```bash
# Enviar a Splunk
python3 -m cybercli.cli siem send splunk "Alerta de seguridad" --host splunk.example.com

# Enviar a ELK
python3 -m cybercli.cli siem send elk "Alerta" --host elk.example.com:9200

# Probar conexión
python3 -m cybercli.cli siem test splunk --host splunk.example.com
```

## Compliance

```bash
# Verificación interactiva
python3 -m cybercli compliance

# Con recomendaciones de IA
python3 -m cybercli compliance --ai

# Desde archivo
python3 -m cybercli compliance --file controles.json

# Ver controles específicos
python3 -m cybercli compliance --controls A.5,A.6
```

## Aprendizaje

```bash
# Análisis de historial
python3 -m cybercli learn

# Ver top 10
python3 -m cybercli learn --top 10

# Con análisis de IA
python3 -m cybercli learn --ai
```

## Exportación

```bash
# Exportar historial
python3 -m cybercli export history archivo.json

# Exportar escaneos específicos
python3 -m cybercli export scan scan_name archivo.json
```

## API REST

```bash
# Iniciar servidor
python3 -m cybercli.cli api --host 0.0.0.0 --port 8000

# Con auto-reload para desarrollo
python3 -m cybercli.cli api --reload
```

### Endpoints

```
GET  /health              # Health check
POST /scan/network       # Escaneo de red
POST /scan/malware       # Escaneo de malware
POST /threatintel        # Query threat intel
POST /cve/query          # Buscar CVE
POST /container/scan     # Escanear contenedores
POST /fim                # File integrity
POST /compliance         # Verificación compliance
GET  /scan/history       # Ver historial
```

## Alertas

```bash
# Alerta por email
python3 -m cybercli alert email admin@example.com --subject "Alerta" --message "Texto"

# Alerta por Slack
python3 -m cybercli alert slack "Mensaje de alerta"

# Alerta por Telegram
python3 -m cybercli alert telegram "Mensaje"
```

## Remediación

```bash
# Sugerir remediaciones
python3 -m cybercli remediation suggest

# Aplicar remediación (simulación)
python3 -m cybercli remediation apply "comando" --simulate

# Aplicar remediación (ejecutar)
python3 -m cybercli remediation apply "comando" --execute

# Rollback
python3 -m cybercli remediation rollback 1
```
