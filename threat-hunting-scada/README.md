# Threat Hunting: respuesta a incidente en infraestructura crítica (SCADA/OT)

> Investigación de un incidente en una subestación eléctrica: análisis de logs de
> Windows, tráfico de red y logs de sistema para reconstruir la intrusión, identificar
> la persistencia del atacante y proponer contención y remediación.

**Tipo:** Threat Hunting / respuesta a incidentes (DFIR)
**Entorno:** laboratorio académico (U-TAD) — escenario de infraestructura crítica
**Marco:** ciclo de respuesta a incidentes **NIST 800-61r2**

> ⚠️ **Nota:** ejercicio de laboratorio con datos de un escenario simulado.

---

## 1. Contexto del incidente

Infraestructura de distribución eléctrica con múltiples subestaciones. Cada una tiene dos
redes separadas por firewall:

- **Red IT** (oficina): conectividad de empleados y sistemas administrativos.
- **Red OT** (industrial): sistemas de control **SCADA**, sensores y actuadores.

La única comunicación autorizada entre ambas es M2M (del servidor de adquisición de datos
**DAS** al de informes). El entorno SCADA solo debería ser accesible desde el **Terminal
Server**, y únicamente desde el cliente Windows autorizado.

**Disparador:** el CERT sectorial reporta tráfico anómalo desde IPs no registradas, y el
personal de planta observa comportamientos extraños en el SCADA.

**Hipótesis inicial:** un atacante ha conectado dispositivos no autorizados a la red y ha
accedido al Terminal Server por RDP para manipular la potencia de salida.

**Plan (NIST 800-61r2):** detección/contención → análisis → erradicación → recuperación →
post-incidente.

---

## 2. Análisis de logs del Terminal Server

`scada-log.txt`: 302 eventos de seguridad de Windows Server 2008. Distribución por Event ID:

| Event ID | Descripción | Nº |
|---|---|---|
| 4907 | Cambios en la política de auditoría de objetos | 70 |
| 4624 | Inicio de sesión exitoso | 51 |
| 4672 | Privilegios especiales asignados | 39 |
| 4735 | Cambio en grupo local de seguridad | 33 |
| 4781 | Cambio de nombre de cuenta | 17 |
| 4720 | **Creación de cuenta de usuario** | 2 |
| 4625 | Fallo de inicio de sesión | 10 |

**Dos IPs no legítimas** realizando autenticaciones RDP:

- `192.168.2.187` — intentos fallidos seguidos de accesos correctos como `Administrador` y
  `usuario1`.
- `192.168.2.201` — múltiples fallos sobre `usuario1`/`usuario2` y finalmente accesos
  correctos.

### Timeline reconstruido

| Fecha/Hora | Origen | Evento | Relevancia |
|---|---|---|---|
| 04/07 12:47 | 192.168.2.187 | 4624/4648 login `Administrador` | Primer acceso remoto no autorizado |
| 04/07 12:57 | Local/.187 | **4720 ×2** creación `usuario1`, `usuario2` | Cuentas backdoor |
| 04/07 13:02 | 192.168.2.201 | 4625 ×3 + 4624 | Dispositivo rogue accediendo |
| 04/07 13:42 | .187 y .201 | Logins simultáneos | Accesos desde dos IPs a la vez |

**Hallazgo clave:** tras entrar como `Administrador`, el atacante crea **dos cuentas**
(`usuario1`, `usuario2`) — técnica de **persistencia** (MITRE ATT&CK **T1136 – Create
Account**): mantienen el acceso aunque se cambie la contraseña del Administrador.

---

## 3. Análisis del tráfico de red

`scada-nmap.nmap`: escaneo de la subred `192.168.2.0/24`. De 255 hosts, 4 responden. Dos son
legítimos (firewall `.100`, Terminal Server `.101`) y **dos no autorizados**:

- **`192.168.2.187`** — Linux con SSH (OpenSSH 6.0), daytime, ident, syslog. Perfil
  **completamente anómalo** en una red industrial → probable **foothold** del atacante.
- **`192.168.2.201`** — todos los puertos **filtrados**: dispositivo deliberadamente oculto,
  pero genera actividad de red → controlado por el atacante.

El análisis del `.pcap` correlaciona esta actividad de red con los accesos RDP vistos en los
logs del Terminal Server.

---

## 4. Análisis del servidor DAS

Revisión de `auth.log` y tareas `cron` del servidor de adquisición de datos, para
comprobar si el atacante saltó de la red IT a la OT a través del único canal M2M autorizado
y si dejó mecanismos de persistencia (tareas programadas).

---

## 5. Contención y remediación propuestas

- **Bloquear** el RDP desde `192.168.2.187` y `192.168.2.201` en el firewall.
- **Eliminar** las cuentas backdoor `usuario1` y `usuario2`.
- **Rotar** la contraseña del `Administrador` y de todas las cuentas privilegiadas.
- **MFA** para los accesos RDP al Terminal Server.
- **Whitelisting de IPs**: solo el cliente autorizado puede alcanzar el Terminal Server.
- **Alertas SIEM** ante creación de cuentas (Event ID **4720**) en sistemas críticos.
- **Revisar la política de auditoría** y revertir los cambios del atacante (eventos 4907).

---

## Ideas clave

- **Threat hunting basado en hipótesis**: se parte de una hipótesis concreta y se busca
  evidencia que la confirme o refute, en lugar de mirar logs a ciegas.
- **Correlación multi-fuente**: los Event IDs de Windows, el escaneo Nmap y el `.pcap`
  cuentan la misma historia desde ángulos distintos; el valor está en cruzarlos.
- **Los Event IDs de Windows como oro forense**: 4720 (creación de cuenta), 4624/4625
  (login OK/fallido), 4672 (privilegios), 4907 (manipulación de la auditoría).
- **Contexto OT/SCADA**: en infraestructura crítica, un acceso que en IT sería menor puede
  tener impacto físico (manipulación de la potencia de salida).

**MITRE ATT&CK:** T1136 (Create Account) · T1021.001 (RDP) · T1078 (Valid Accounts) ·
T1562.002 (Impair Defenses: manipulación de la auditoría)
