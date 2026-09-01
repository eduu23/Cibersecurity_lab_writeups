# Security Lab Writeups — Eduardo Lucas Guinea

Documentación técnica de auditorías, ejercicios de red team y análisis forense que he
realizado en entornos de laboratorio durante mi formación en ciberseguridad (U-TAD),
con especialización en hacking ético.

El objetivo de este repositorio es mostrar **cómo trabajo**: metodología, razonamiento
detrás de cada decisión y documentación clara de principio a fin — no solo el resultado.

> ⚠️ Todo el contenido procede de **laboratorios controlados y autorizados**. Las
> credenciales, hashes y flags aparecen **ofuscados** de forma deliberada: el foco está
> en la técnica, no en reproducir datos de los escenarios.

---

## Writeups

| Writeup | Área | Técnicas clave |
|---|---|---|
| [Compromiso de dominio Active Directory vía pivoting por DMZ](active-directory-domain-compromise/) | Red Team / AD | Pivoting HTTP (Neo-reGeorg), Pass-the-Hash, Kerberoasting, DCSync |
| [Auditoría de intrusión sobre infraestructura Linux](auditoria-intrusion-linux/) | Pentesting web/sistemas | SQLi, SQLMap, RCE (ProFTPD, Drupal), Metasploit, PwnKit |
| [Análisis forense y respuesta a incidentes (DFIR)](dfir-analisis-forense/) | Forense | FTK Imager, Volatility, Wireshark, gdb, Pestudio, esteganografía |
| [Despliegue seguro: Docker, Kubernetes y CI/CD](despliegue-seguro-devsecops/) | DevSecOps / Bastionado | Docker Compose, k3s, Sealed Secrets, Prometheus/Grafana, Jenkins, SonarQube |
| [Threat Hunting: incidente en infraestructura crítica (SCADA/OT)](threat-hunting-scada/) | Threat Hunting / DFIR | Event IDs de Windows, análisis de red, timeline, NIST 800-61, MITRE |
| [Bastionado de redes y sistemas (hardening)](bastionado-hardening/) | Bastionado / Blue Team | Endpoints, identidades (PAM/SSH), SQL Server (TDE), DLP, cadena de suministro |

---

## Áreas de trabajo

- **Hacking ético / Red Team** — enumeración, explotación, pivoting multi-salto,
  post-explotación y ataques a Active Directory.
- **Análisis forense (DFIR) y threat hunting** — adquisición de evidencias, análisis de
  memoria RAM, forense de red, análisis de malware y respuesta a incidentes.
- **Bastionado y despliegue seguro** — hardening, contenedores (Docker/Kubernetes) y CI/CD.

## Certificaciones

- **eJPT** (INE / eLearnSecurity) — Junior Penetration Tester
- **CompTIA Security+** — en curso

## Contacto

- LinkedIn: _(añade tu enlace)_
