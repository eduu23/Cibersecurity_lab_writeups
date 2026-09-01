# Bastionado de redes y sistemas (hardening)

> Recorrido por las distintas capas del endurecimiento de sistemas trabajadas en
> laboratorio: endpoints, identidades, bases de datos, datos, y cadena de suministro,
> con un enfoque práctico de "configurar, verificar y evidenciar".

**Tipo:** Bastionado / defensa (Blue Team)
**Entorno:** laboratorio académico (U-TAD)

> ⚠️ **Nota:** trabajo de laboratorio. Se resume el enfoque y las medidas aplicadas en
> cada área; el foco es la metodología de hardening.

---

## 1. Hardening de endpoints e identidades

Endurecimiento de sistemas Linux centrado en autenticación y control de acceso:

- **Política de contraseñas** robusta (complejidad mínima, caracteres especiales) vía PAM.
- **Bloqueo de cuentas** tras 5 intentos fallidos durante 10 minutos (`pam_tally2`/`faillock`)
  para frenar la fuerza bruta.
- **Hardening de SSH**: revisión de la configuración del servicio para reducir su superficie
  de exposición.
- Reflexión sobre la **calidad real de las contraseñas** (longitud > complejidad artificial):
  una passphrase larga y memorizable es más fuerte y usable que una corta con símbolos.

## 2. Hardening de bases de datos (SQL Server)

- Verificación y deshabilitación de cuentas por defecto (`guest`).
- **Políticas de contraseña** a nivel de motor (`MUST_CHANGE`, `CHECK_EXPIRATION`,
  `CHECK_POLICY`).
- **Cifrado TDE** (Transparent Data Encryption): creación del certificado y cifrado de la
  base de datos en reposo.
- Reglas de **firewall** específicas para el servicio.

## 3. Protección de datos y prevención de fugas (DLP)

- Configuración de políticas orientadas a **proteger información sensible** y evitar su
  exfiltración.
- **Políticas de bloqueo** que reaccionan ante acciones que violan las reglas definidas.

## 4. Seguridad de la cadena de suministro

- Análisis de un **pipeline de build** (clonado, actualización, empaquetado del software)
  desde la óptica de la seguridad de la cadena de suministro.
- Revisión de qué comandos ejecuta cada actor del pipeline y con qué restricciones, para
  limitar el impacto de un componente comprometido.

## 5. Análisis de amenazas (threat intel)

- Estudio de **APTs** y de sus TTPs (por ejemplo, el abuso de **PowerShell** para ejecución,
  descubrimiento y evasión), relacionando técnicas reales con el marco MITRE ATT&CK.
- Contextualización de objetivos habituales de estos grupos: gobiernos, infraestructuras
  críticas y cadenas de suministro de software.

---

## Ideas clave

- **Defensa en profundidad**: el bastionado no es una sola medida, sino capas —
  identidades, endpoints, datos, servicios y cadena de suministro.
- **Configurar, verificar y evidenciar**: cada medida se acompaña de una prueba de que
  realmente funciona (bloqueo efectivo, cifrado activo, regla aplicada).
- **Usabilidad y seguridad**: las políticas demasiado rígidas se sortean; el objetivo es
  seguridad *aplicable* (p. ej. passphrases largas frente a complejidad artificial).
- **Normativa como guía**: el hardening se apoya en marcos y buenas prácticas del sector,
  no en decisiones arbitrarias.

## Áreas cubiertas

Endpoints · Identidades y autenticación (PAM, SSH) · Bases de datos (SQL Server, TDE) ·
Protección de datos / DLP · Cadena de suministro · Threat intelligence (APTs, MITRE ATT&CK)
