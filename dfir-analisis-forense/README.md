# Análisis forense y respuesta a incidentes (DFIR)

> Recorrido por las cinco disciplinas del análisis forense digital trabajadas en
> laboratorio: adquisición de evidencias, análisis de memoria RAM, forense de disco
> en Linux, forense de red y análisis de malware.

**Tipo:** Digital Forensics & Incident Response (DFIR)
**Entorno:** laboratorio académico (U-TAD)

> ⚠️ **Nota:** ejercicios en laboratorio controlado. Las *flags* y datos concretos de
> cada caso se han omitido u ofuscado; el objetivo es documentar la **metodología y las
> herramientas** de cada disciplina forense.

---

## Índice

1. [Adquisición de evidencias y esteganografía](#1-adquisición-de-evidencias-y-esteganografía)
2. [Análisis de memoria RAM (Volatility)](#2-análisis-de-memoria-ram-volatility)
3. [Forense de disco en Linux](#3-forense-de-disco-en-linux)
4. [Forense de red (Wireshark)](#4-forense-de-red-wireshark)
5. [Análisis de malware](#5-análisis-de-malware)

---

## 1. Adquisición de evidencias y esteganografía

Fase fundamental del DFIR: preservar la evidencia garantizando su integridad y una
**cadena de custodia** correcta.

**Imágenes forenses y clonado:**

- Adquisición con **FTK Imager** en formato **E01**, rellenando metadatos del caso
  (número de caso, evidencia, examinador).
- Clonado físico y verificación de integridad con hashes **MD5 / SHA1**; al finalizar,
  se comparan los hashes calculados con los de referencia para probar que la copia es
  idéntica al original.
- Clonado por línea de comandos con `dcfldd` calculando el hash en el proceso:

```bash
dcfldd if=/dev/sdX of=clonado.img hash=sha256 hashlog=hashlog.txt
sha1sum clonado.img   # verificación contra el hash de referencia
```

- Imágenes cifradas con certificado (AD Encryption): la imagen solo se monta aportando
  el certificado y su contraseña.
- Cumplimentación del documento de **cadena de custodia**.

**Esteganografía y análisis de ficheros:**

```bash
exiftool documento.pdf          # metadatos (software, fechas de creación)
binwalk -D='.*' imagen.png      # extrae ficheros ocultos embebidos
stegseek imagen.jpg rockyou.txt # rompe esteganografía protegida por contraseña
xxd fichero.odt | head          # identifica el tipo real vs. la extensión falsa
```

Un fichero con extensión `.odt` que en realidad es texto plano se detecta comparando la
extensión con el *File Type* real (exiftool / cabecera con `xxd`).

**Cracking de contenedores protegidos:**

```bash
zip2john Imagen.zip > hash.txt
john --wordlist=diccionario.txt --rules=best64 hash.txt
```

---

## 2. Análisis de memoria RAM (Volatility)

Análisis de volcados de memoria (`.vmem`) de máquinas Windows para reconstruir la
actividad en el momento de la captura.

Flujo de trabajo:

```bash
# 1. Identificar el perfil del volcado
vol.py -f volcado.vmem imageinfo

# 2. Con el perfil sugerido, extraer artefactos
vol.py -f volcado.vmem --profile=Win7SP1x64 hashdump       # hashes de cuentas
vol.py -f volcado.vmem --profile=Win7SP1x64 consoles       # comandos ejecutados
vol.py -f volcado.vmem --profile=Win7SP1x64 shutdowntime   # hora de apagado
vol.py -f volcado.vmem --profile=WinXPSP2x86 connscan      # conexiones de red
vol.py -f volcado.vmem --profile=WinXPSP2x86 pslist        # procesos activos
vol.py -f volcado.vmem --profile=WinXPSP2x86 malfind -p <PID>  # inyección de código
```

Otros artefactos recuperados de la RAM: contenido del **portapapeles** (con
InsideClipboard de NirSoft), procesos sospechosos (Process Explorer/Hacker), servicios
(`wmic service`) y passphrases de contenedores cifrados en memoria.

---

## 3. Forense de disco en Linux

Análisis de una imagen de disco multi-partición para reconstruir la actividad y detectar
persistencia/backdoors.

Puntos clave del análisis:

- **Identificación de particiones**: distinguir Windows (Boot, Recovery) de Linux por su
  estructura; la partición `ext4` resultó ser un Kali (rolling).
- **Usuarios y privilegios**: listado de usuarios con shell (`/bin/bash`), extracción de
  hashes de `/etc/shadow`, y detección de anomalías — `www-data` añadido al grupo `root`
  (debería ser de bajos privilegios) y un usuario `news` con **UID 0** usado como
  **backdoor**.
- **Configuración de `sudo`**: análisis de qué puede ejecutar cada usuario como root.
- **Sesiones y accesos**: usuarios logueados, conexiones remotas y últimos accesos.
- **Persistencia**: regla de `cron` (`0 * * * *`) que se ejecuta cada hora.
- **Análisis de logs**: verificación de integridad de `/var/log/apache2` con hash MD5 y
  revisión del `.bash_history` de root para reconstruir la línea temporal de comandos.

---

## 4. Forense de red (Wireshark)

Análisis de una captura de tráfico (`.pcap`) para reconstruir un incidente: identificar
al atacante, el canal de mando y control y la exfiltración.

Filtros de Wireshark empleados:

```
tcp.port == 443 && !tls          # tráfico en 443 que NO es TLS (sospechoso)
dns                              # miles de peticiones a un dominio C2
ftp || http                     # herramienta usada por el atacante
ip.src == 192.168.0.121 && tcp.len > 0 && !ftp
frame contains ".tgz"           # localización de archivos exfiltrados
```

El análisis permitió: identificar el patrón de **beaconing a un dominio C2** vía DNS,
confirmar la herramienta usada por el atacante (por los protocolos FTP/HTTP), y localizar
los ficheros exfiltrados (`.tgz`) siguiendo los streams TCP.

---

## 5. Análisis de malware

Análisis estático y dinámico de un ejecutable sospechoso para determinar su naturaleza y
capacidades.

**Análisis estático:**

- **Pestudio** — identificación del lenguaje (.NET) y de los *imports* sospechosos
  (`advapi32.dll`, `bcrypt.dll`, `crypt32.dll` → capacidades de cifrado).
- **VirusTotal** — baja detección (3/72), un recordatorio de que un veredicto limpio no
  garantiza que sea inofensivo; el análisis manual de los imports fue decisivo.

**Análisis dinámico y reversing:**

- **gdb** — depuración del binario para seguir la lógica (`break main`, `run`), con
  símbolos para asociar direcciones de memoria al código.
- Identificación de técnicas de evasión: **Dropper/Loader** que descifra (XOR) un binario
  embebido y lo carga como **DLL directamente en memoria** (sin tocar disco), pasándole
  cadenas en Base64.
- Verificación de comportamiento en red: primer paquete TCP (SYN) hacia el servidor del
  atacante y bucle a la escucha de comandos.

**Conclusión del caso:** pese al bajo score en VirusTotal, el análisis de imports y de
comportamiento determinó que el binario era un **keylogger** con capacidades básicas de
comunicación con el atacante.

---

## Herramientas por disciplina

| Disciplina | Herramientas |
|---|---|
| Adquisición | FTK Imager, dcfldd, exiftool, binwalk, stegseek, John the Ripper |
| Memoria RAM | Volatility, InsideClipboard, Process Explorer |
| Disco Linux | análisis de particiones, `/etc/shadow`, cron, logs, `.bash_history` |
| Red | Wireshark |
| Malware | gdb, Pestudio, VirusTotal |

**Mapa ATT&CK (defensa):** el análisis cubre detección de T1547 (persistencia),
T1071 (C2 sobre protocolos de aplicación), T1055 (inyección de procesos) y
T1056.001 (keylogging).
