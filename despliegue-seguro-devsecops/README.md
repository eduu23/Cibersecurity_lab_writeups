# Despliegue seguro: Docker, Kubernetes y CI/CD

> Puesta en producción segura de aplicaciones contenerizadas: desde un despliegue
> multi-contenedor con monitorización, pasando por la administración y fortificación
> de un clúster Kubernetes, hasta un pipeline de CI/CD completo con quality gate.

**Tipo:** DevSecOps / despliegue seguro
**Entorno:** laboratorio académico (U-TAD) · Ubuntu Server

> ⚠️ **Nota:** trabajo de laboratorio. IPs, tokens y credenciales corresponden a la red
> privada del entorno y se muestran de forma ilustrativa.

Este writeup reúne dos trabajos complementarios: (1) despliegue con Docker Compose +
monitorización + fortificación de un clúster k3s, y (2) un pipeline de CI/CD que compila
y publica un sistema operativo completo (ToaruOS).

---

## Parte 1 — Docker, Compose y clúster Kubernetes

### 1.1. Aplicación web multi-contenedor con monitorización

Despliegue sobre Ubuntu Server, orquestado con **Docker Compose**, de una aplicación web
con parte pública y parte autenticada **real**, más un stack de monitorización.

**Aplicación (Flask):**
- Python + **Flask**, `Flask-SQLAlchemy` (ORM sobre **SQLite**), `Flask-Login` (sesiones) y
  `gunicorn` como servidor WSGI de producción.
- Contraseñas almacenadas como **hash** (werkzeug), no en claro.
- Control de acceso aplicado **en servidor** con `login_required`: al pedir `/dashboard`
  sin sesión, la app redirige al login — se verifica que la autenticación es real y no
  cosmética.
- Contenerización con Dockerfile propio (imagen ligera de Python, dependencias en capa
  cacheable, `gunicorn` en el puerto 5000).

**Monitorización (Prometheus + Grafana):**
- `docker-compose.yml` con cinco servicios (app, Prometheus, cAdvisor, node-exporter,
  Grafana) sobre una red bridge interna; Prometheus alcanza a los exportadores por nombre
  de servicio.
- Métricas del **motor de Docker** (`daemon.json` con `metrics-addr`), de los
  **contenedores** (cAdvisor) y del **host** (node-exporter).
- **Persistencia** con volúmenes nombrados (`db_data`, `prom_data`, `grafana_data`).
- Grafana aprovisionado por ficheros (datasource + dashboards en JSON) para que la
  configuración sea **reproducible y versionable**.

**Endurecimiento del acceso:** Grafana se publica **solo en `127.0.0.1:3000`**, de modo que
verlo desde el host obliga a un **túnel SSH con reenvío de puertos** (`ssh -L 3000:...`).

> **Problemas resueltos** (lo que de verdad enseña la práctica):
> - El paquete `docker.io` de Ubuntu no trae Compose v2 → instalación del plugin desde
>   *universe* (`docker-compose-v2`).
> - `permission denied` en `/var/run/docker.sock` → `usermod -aG docker` + nueva sesión.
> - Especificador de versión inválido en `requirements.txt` (`gunicorn=22.0.0` →
>   `gunicorn==22.0.0`).
> - El endpoint de métricas del daemon debía enlazar a `0.0.0.0:9323` y no a loopback,
>   porque Prometheus (en contenedor) alcanza el host por `host.docker.internal`, no por
>   loopback.

### 1.2. Administración y fortificación de un clúster k3s multinodo

Sobre un clúster **k3s** de tres nodos (1 control-plane + 2 workers) en red Host-Only
`192.168.56.0/24`, ejecutando una app distribuida (API, workers, frontend, Redis,
PostgreSQL y un registro de imágenes privado).

**Reemplazo de un nodo en caliente** (sin perder el estado `Ready` global):

```bash
kubectl drain k3s-agent-2 --ignore-daemonsets --delete-emptydir-data  # vaciado controlado
kubectl delete node k3s-agent-2                                        # baja del clúster
# nuevo nodo k3s-agent-3 (192.168.56.13): instalación de k3s apuntando al server + token
```

Los pods se reprograman en los nodos restantes durante el drenaje; tras registrar el nuevo
agente, el clúster vuelve a tres nodos operativos.

**Fortificación con Sealed Secrets:** el manifiesto original guardaba las credenciales de
PostgreSQL en **Base64 plano** (que no es cifrado). Se implementó **Sealed Secrets**
(Bitnami):

```bash
# controlador en kube-system + cliente kubeseal en el host
kubeseal < 01-secrets.yaml > 01-sealed-secrets.yaml   # cifrado asimétrico con la clave pública
kubectl delete secret db-credentials                  # se elimina el secreto en claro
kubectl apply -f 01-sealed-secrets.yaml               # el controlador lo descifra en el clúster
```

Resultado: los valores sensibles quedan en un bloque `encryptedData` que **sí puede
versionarse en Git de forma segura**; el controlador los descifra internamente y genera el
`Secret` estándar que consumen los pods, sin cambios para la aplicación.

---

## Parte 2 — Pipeline CI/CD (Jenkins + SonarQube + Gitea)

Pipeline que compila y publica **ToaruOS** (un SO Unix-like completo escrito en C) de forma
automática, con análisis de calidad como paso obligatorio.

**Componentes:** **Gitea** (repositorio Git local), **SonarQube** (quality gate) y
**Jenkins** (orquestador: dispara SonarQube y, si pasa, compila y despliega).

**Flujo montado:**

1. **Compilación reproducible con Docker** — imagen oficial `toaruos/build-tools` con el
   toolchain de compilación cruzada; el repo se monta como volumen y `build-in-docker.sh`
   genera la ISO booteable.
2. **Código en Gitea** — repositorio `toaruos`, push del código fuente completo.
3. **SonarQube** — proyecto `toaruos` con `sonar-project.properties`; el análisis final da
   **estado Passed**, 0 problemas de seguridad sobre ~1.3k líneas en 6 lenguajes.
4. **Jenkins Multibranch Pipeline** — fuente Gitea, escaneo periódico; `Jenkinsfile` con
   tres stages: **análisis SonarQube → compilación → publicación de la ISO como release en
   Gitea**.
5. **Verificación** — se descarga la ISO generada por el pipeline y se arranca en una VM
   nueva: ToaruOS bootea correctamente (escritorio Yutani).

> **Problemas resueltos** (depuración real de un pipeline):
> - `SonarQube server [http://localhost:9000] can not be reached` → fijar la IP explícita
>   del servidor con `-Dsonar.host.url`.
> - `permission denied` en el socket de Docker desde Jenkins → añadir `jenkins` al grupo
>   `docker` vía `DOCKER_GID` en `.env` (Docker-in-Docker).
> - Ficheros copiados con `docker cp` como `root` (UID 0) → `docker exec ... chown` antes
>   de compilar.
> - **`exit code 137` (OOM killer)** — Jenkins + SonarQube + Gitea + el build superaban la
>   RAM disponible; se detuvo SonarQube durante la compilación (su análisis ya había
>   terminado) para liberar memoria y completar el build.

---

## Ideas clave

- **Seguridad en el despliegue, no solo en el código**: segmentación de red, exposición
  mínima (Grafana solo en loopback + túnel SSH), persistencia y gestión segura de secretos.
- **Secretos versionables**: Sealed Secrets permite tener el manifiesto en Git sin exponer
  credenciales — Base64 **no** es cifrado.
- **Quality gate en el pipeline**: SonarQube como condición para desplegar integra la
  seguridad en el ciclo de vida (DevSecOps).
- **Depuración de infraestructura real**: permisos de Docker, Docker-in-Docker, OOM killer,
  binding de endpoints... los problemas que aparecen fuera del "camino feliz".

## Herramientas

Docker · Docker Compose · Kubernetes / k3s · `kubectl` · Sealed Secrets (kubeseal) ·
Prometheus · Grafana · cAdvisor · node-exporter · Flask / gunicorn · Jenkins · SonarQube ·
Gitea · Git
