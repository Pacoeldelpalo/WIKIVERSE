import hashlib   # Para calcular hashes (contraseñas y tokens)
import json      # Para leer el catálogo de la biblioteca (catalogo.json)
import math      # Para calcular distancias entre coordenadas del cielo
import os        # Para leer variables de entorno (carpeta de imágenes)
import hmac      # Para comparar hashes de forma segura
import re        # Expresiones regulares (validar email y LinkedIn)
import secrets   # Para generar números aleatorios seguros (sal y tokens)
import sqlite3   # Base de datos SQLite (viene incluida en Python)
import time      # Para trabajar con la hora actual (caducidad de sesiones)
from datetime import datetime, timezone   # Para guardar la fecha del consentimiento
from pathlib import Path                  # Para construir rutas de archivos
from typing import Optional               # Para campos opcionales

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware   # Permite que la web llame a la API
from fastapi.responses import FileResponse           # Para devolver index.html
from fastapi.staticfiles import StaticFiles          # Para servir las imágenes de la biblioteca
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer   # Esquema Bearer (botón Authorize)
from pydantic import BaseModel, Field    # Para definir y validar los datos que llegan


# CREACIÓN DE LA APLICACIÓN

# persistAuthorization hace que Swagger recuerde el token al recargar la página
app = FastAPI(swagger_ui_parameters={"persistAuthorization": True})

# CORS: por defecto, un navegador bloquea las peticiones de una página web
# a una API que está en otra dirección. Esta configuración las permite.
# "*" significa "cualquier origen": cómodo para pruebas, pero antes de
# publicar la web conviene restringirlo a tu dominio.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],   # incluye la cabecera Authorization que usamos para el token
)


# BASE DE DATOS

# Nombre del archivo de la base de datos (se crea solo si no existe)
DB = "wikiverse.db"


def get_conn():
    """Abre una conexión nueva a la base de datos."""
    conn = sqlite3.connect(DB)
    # Con esto las filas se pueden leer por nombre de columna: fila["email"]
    conn.row_factory = sqlite3.Row
    # SQLite trae desactivadas las claves foráneas; esto las activa
    # (necesario para que "ON DELETE CASCADE" funcione)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# Crea las tablas al arrancar la API. "IF NOT EXISTS" evita errores
# (y no borra datos) si las tablas ya existían.
with get_conn() as conn:

    # Tabla de mensajes (de las primeras pruebas; ahora no tiene endpoints)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mensajes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            texto TEXT NOT NULL,
            creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Tabla de usuarios registrados: cada registro nuevo añade una fila aquí
    conn.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,          -- UNIQUE: no puede haber dos cuentas con el mismo email
            password_hash TEXT NOT NULL,         -- nunca se guarda la contraseña, solo su hash
            linkedin_url TEXT,                   -- opcional
            acepta_compartir_datos INTEGER NOT NULL DEFAULT 0,   -- 1 = sí acepta, 0 = no
            consentimiento_en TEXT,              -- fecha en que dio su consentimiento
            creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Tabla de sesiones: cada inicio de sesión genera un token que se guarda aquí
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sesiones (
            token_hash TEXT PRIMARY KEY,         -- el token se guarda hasheado, no tal cual
            usuario_id INTEGER NOT NULL,
            expira_en INTEGER NOT NULL,          -- momento en que caduca (segundos desde 1970)
            -- Si se borra un usuario, se borran también sus sesiones
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
        )
    """)

    # Biblioteca de imágenes: un objetivo es un objeto del cielo (p. ej. Barnard's Star)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS objetivos (
            key TEXT PRIMARY KEY,                -- identificador corto, p. ej. "barnards"
            orden INTEGER NOT NULL,              -- para mostrarlos siempre en el mismo orden
            nombre TEXT NOT NULL,
            tipo TEXT NOT NULL,
            ra_deg REAL NOT NULL,                -- ascensión recta en grados (J2000)
            dec_deg REAL NOT NULL,               -- declinación en grados (J2000)
            overview_imagen TEXT NOT NULL,       -- imagen de contexto (WISE) de campo amplio
            overview_survey TEXT,
            overview_banda TEXT,
            overview_campo TEXT,
            overview_fuente TEXT
        )
    """)

    # Cada visita es una exposición de SPHEREx: una imagen de un objetivo, en una banda, un día
    conn.execute("""
        CREATE TABLE IF NOT EXISTS visitas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            objetivo_key TEXT NOT NULL,
            banda TEXT NOT NULL,                 -- D1 ... D6
            fecha TEXT NOT NULL,                 -- AAAA-MM-DD (UTC)
            hora TEXT NOT NULL,                  -- HH:MM:SS (UTC)
            mjd REAL NOT NULL,                   -- fecha juliana modificada
            imagen TEXT NOT NULL,                -- ruta dentro de la carpeta spherex-images
            obs_id TEXT NOT NULL,
            coleccion TEXT NOT NULL,
            fuente TEXT NOT NULL,                -- enlace al producto original en IRSA
            epoca TEXT,
            grupo INTEGER NOT NULL,
            grupo_frame INTEGER NOT NULL,
            dias_grupo_previo REAL,              -- NULL en el primer grupo
            FOREIGN KEY (objetivo_key) REFERENCES objetivos(key) ON DELETE CASCADE
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_visitas_objetivo ON visitas(objetivo_key, banda)")

    # Anomalías que reportan los usuarios desde el comparador de píxeles
    conn.execute("""
        CREATE TABLE IF NOT EXISTS anomalias (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id INTEGER NOT NULL,
            objetivo_key TEXT NOT NULL,
            banda TEXT NOT NULL,
            obs_a TEXT NOT NULL,
            obs_b TEXT NOT NULL,
            fecha_a TEXT NOT NULL,               -- se copian de la biblioteca, no del cliente
            fecha_b TEXT NOT NULL,
            offset_px REAL NOT NULL,
            offset_arcsec REAL NOT NULL,
            offset_sigma REAL NOT NULL,
            cambio_brillo REAL NOT NULL,         -- cambio relativo (0.12 = +12 %)
            brillo_sigma REAL NOT NULL,
            n_refs INTEGER NOT NULL,
            metodo TEXT NOT NULL,
            estado TEXT NOT NULL DEFAULT 'unverified_candidate',
            nota TEXT,
            creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            -- Un usuario no puede reportar dos veces el mismo par de exposiciones
            UNIQUE (usuario_id, objetivo_key, banda, obs_a, obs_b),
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
            FOREIGN KEY (objetivo_key) REFERENCES objetivos(key) ON DELETE CASCADE
        )
    """)


# USUARIOS: CONSTANTES Y FUNCIONES AUXILIARES

ITERACIONES = 600_000            # Cuántas veces se repite el cálculo del hash (más = más seguro, más lento)
SESION_SEG = 7 * 24 * 3600       # Las sesiones duran 7 días (en segundos)

# Un email válido: algo, una @, algo, un punto y algo (comprobación sencilla)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Una URL de LinkedIn válida: https://www.linkedin.com/in/loquesea
LINKEDIN_RE = re.compile(
    r"^https://([a-z]{2,3}\.)?(www\.)?linkedin\.com/(in|pub)/[^\s]+$", re.IGNORECASE
)


def hashear_password(password: str) -> str:
    """Convierte la contraseña en un hash con sal aleatoria.
    Nunca se guarda la contraseña en texto plano."""
    # La "sal" es un valor aleatorio distinto para cada usuario. Así, dos
    # personas con la misma contraseña tienen hashes diferentes.
    sal = secrets.token_bytes(16)
    # PBKDF2: algoritmo pensado para contraseñas, deliberadamente lento
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), sal, ITERACIONES)
    # Se guarda todo junto en un texto: algoritmo$iteraciones$sal$hash
    return f"pbkdf2_sha256${ITERACIONES}${sal.hex()}${h.hex()}"


def verificar_password(password: str, guardado: str) -> bool:
    """Comprueba si una contraseña coincide con el hash guardado."""
    try:
        # Separa las 4 partes del texto guardado
        _, iteraciones, sal_hex, h_hex = guardado.split("$")
        # Calcula el hash de la contraseña recibida con la misma sal
        h = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(sal_hex), int(iteraciones)
        )
        # compare_digest compara sin revelar, por el tiempo que tarda,
        # en qué punto empiezan a diferir los textos
        return hmac.compare_digest(h.hex(), h_hex)
    except Exception:
        # Si el hash guardado está mal formado, se considera no válida
        return False


# Hash de relleno: se usa en el login cuando el email no existe, para que
# la respuesta tarde lo mismo exista o no la cuenta (así no se puede
# averiguar qué emails están registrados midiendo tiempos)
HASH_FALSO = hashear_password("relleno-no-es-una-contraseña")


def hash_token(token: str) -> str:
    """Calcula el hash del token. En la base de datos se guarda el hash,
    de modo que, aunque alguien lea la base de datos, no puede usar los tokens."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def crear_sesion(conn, usuario_id: int) -> str:
    """Crea una sesión nueva para el usuario y devuelve el token."""
    # Token aleatorio imposible de adivinar (el cliente lo recibe una sola vez)
    token = secrets.token_urlsafe(32)
    # En la base de datos se guarda su hash y la fecha de caducidad
    conn.execute(
        "INSERT INTO sesiones (token_hash, usuario_id, expira_en) VALUES (?, ?, ?)",
        (hash_token(token), usuario_id, int(time.time()) + SESION_SEG),
    )
    return token


def datos_publicos(fila) -> dict:
    """Selecciona los datos del usuario que se pueden enviar al cliente.
    Nunca incluye el hash de la contraseña."""
    return {
        "id": fila["id"],
        "nombre": fila["nombre"],
        "email": fila["email"],
        "linkedin_url": fila["linkedin_url"],
        "acepta_compartir_datos": bool(fila["acepta_compartir_datos"]),   # 0/1 -> False/True
        "consentimiento_en": fila["consentimiento_en"],   # fecha del consentimiento (None si no lo dio)
        "creado_en": fila["creado_en"],
    }


# Esquema Bearer: hace que Swagger muestre el botón "Authorize" y envíe
# la cabecera Authorization en las peticiones.
# auto_error=False para devolver nosotros mismos el mensaje de error en español.
esquema_bearer = HTTPBearer(auto_error=False)


def usuario_actual(
    credenciales: Optional[HTTPAuthorizationCredentials] = Depends(esquema_bearer),
):
    """Dependencia de FastAPI: se usa en los endpoints que exigen sesión.
    Lee la cabecera 'Authorization: Bearer <token>' y devuelve el usuario."""
    # Si no llega la cabecera (o no es de tipo Bearer), no hay sesión
    if credenciales is None:
        raise HTTPException(status_code=401, detail="Falta el token de sesión.")
    # FastAPI ya separó la palabra "Bearer": aquí solo queda el token
    token = credenciales.credentials.strip()
    with get_conn() as conn:
        # Busca una sesión con ese token que no haya caducado
        # y trae los datos del usuario al que pertenece
        fila = conn.execute(
            """SELECT u.* FROM sesiones s
               JOIN usuarios u ON u.id = s.usuario_id
               WHERE s.token_hash = ? AND s.expira_en > ?""",
            (hash_token(token), int(time.time())),
        ).fetchone()
    # Si no hay ninguna, el token no existe o ha caducado
    if fila is None:
        raise HTTPException(status_code=401, detail="Sesión no válida o caducada.")
    return fila


# MODELOS: FORMA DE LOS DATOS QUE LLEGAN A LA API

class RegistroIn(BaseModel):
    """Datos que envía la web al registrarse."""
    nombre: str = Field(min_length=1, max_length=100)
    email: str = Field(max_length=254)
    password: str = Field(min_length=8, max_length=128)    # mínimo 8 caracteres
    linkedin_url: Optional[str] = Field(default=None, max_length=300)   # opcional
    acepta_compartir_datos: bool = False    # casilla de consentimiento


class PerfilIn(BaseModel):
    """Datos que envía la web al guardar los cambios de su perfil."""
    nombre: str = Field(min_length=1, max_length=100)
    linkedin_url: Optional[str] = Field(default=None, max_length=300)
    acepta_compartir_datos: bool


class LoginIn(BaseModel):
    """Datos que envía la web al iniciar sesión."""
    email: str = Field(max_length=254)
    password: str = Field(max_length=128)


# ENDPOINTS DE USUARIOS

@app.post("/auth/registro", status_code=201)
def registrar_usuario(datos: RegistroIn):
    """Crea una cuenta nueva y deja al usuario con la sesión iniciada."""

    # Normaliza el email (sin espacios y en minúsculas) para que
    # "Ana@x.com" y "ana@x.com" sean la misma cuenta
    email = datos.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=422, detail="El email no es válido.")

    # El LinkedIn es opcional: si viene vacío se guarda como None.
    # Si viene, debe tener el formato de un perfil de LinkedIn.
    linkedin = (datos.linkedin_url or "").strip() or None
    if linkedin and not LINKEDIN_RE.match(linkedin):
        raise HTTPException(
            status_code=422,
            detail="La URL de LinkedIn debe ser como https://www.linkedin.com/in/tu-perfil",
        )

    # Si el usuario acepta compartir sus datos, se guarda la fecha y hora
    # exactas (en UTC) en que lo aceptó
    consentimiento_en = (
        datetime.now(timezone.utc).isoformat() if datos.acepta_compartir_datos else None
    )

    # Convierte la contraseña en hash antes de guardarla
    password_hash = hashear_password(datos.password)

    try:
        with get_conn() as conn:
            # Inserta el usuario nuevo: así se "guarda en la lista"
            cur = conn.execute(
                """INSERT INTO usuarios
                   (nombre, email, password_hash, linkedin_url,
                    acepta_compartir_datos, consentimiento_en)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (datos.nombre.strip(), email, password_hash, linkedin,
                 int(datos.acepta_compartir_datos), consentimiento_en),
            )
            usuario_id = cur.lastrowid               # id que se le acaba de asignar
            token = crear_sesion(conn, usuario_id)   # inicia sesión automáticamente
            # Vuelve a leer el usuario para devolver sus datos
            fila = conn.execute(
                "SELECT * FROM usuarios WHERE id = ?", (usuario_id,)
            ).fetchone()
    except sqlite3.IntegrityError:
        # Salta si el email ya existe (por la restricción UNIQUE de la tabla)
        raise HTTPException(status_code=409, detail="Ya existe una cuenta con ese email.")

    return {"token": token, "usuario": datos_publicos(fila)}


@app.post("/auth/login")
def iniciar_sesion(datos: LoginIn):
    """Comprueba el email y la contraseña, y devuelve un token de sesión."""
    email = datos.email.strip().lower()
    with get_conn() as conn:
        # Aprovecha para borrar las sesiones que ya han caducado
        conn.execute("DELETE FROM sesiones WHERE expira_en < ?", (int(time.time()),))

        # Busca al usuario por su email
        fila = conn.execute(
            "SELECT * FROM usuarios WHERE email = ?", (email,)
        ).fetchone()

        # Verifica la contraseña. Si el usuario no existe, compara contra el
        # hash de relleno para que el tiempo de respuesta sea el mismo.
        ok = verificar_password(
            datos.password, fila["password_hash"] if fila else HASH_FALSO
        )

        # El mensaje de error es el mismo si falla el email o la contraseña,
        # para no revelar qué emails están registrados
        if fila is None or not ok:
            raise HTTPException(status_code=401, detail="Email o contraseña incorrectos.")

        token = crear_sesion(conn, fila["id"])   # genera el token de esta sesión
    return {"token": token, "usuario": datos_publicos(fila)}

# endpoint para obtener los datos del usuario que tiene la sesión iniciada
@app.get("/auth/me")
def obtener_mi_perfil(usuario=Depends(usuario_actual)):
    """
    Devuelve los datos del usuario que tiene la sesión iniciada.
    """
    return datos_publicos(usuario)


# endpoint para que el usuario cambie sus propios datos (nombre, LinkedIn y consentimiento)
@app.put("/auth/me")
def actualizar_mi_perfil(datos: PerfilIn, usuario=Depends(usuario_actual)):
    """
    Actualiza el perfil del usuario con la sesión iniciada.
    El email no se puede cambiar: es lo que identifica la cuenta.
    """
    nombre = datos.nombre.strip()
    if not nombre:
        raise HTTPException(status_code=422, detail="El nombre no puede estar vacío.")

    linkedin = (datos.linkedin_url or "").strip() or None
    if linkedin and not LINKEDIN_RE.match(linkedin):
        raise HTTPException(
            status_code=422,
            detail="La URL de LinkedIn debe ser como https://www.linkedin.com/in/tu-perfil",
        )

    # La fecha del consentimiento solo cambia cuando cambia la casilla:
    # si pasa a "sí" se guarda la hora actual; si pasa a "no" se borra (retira el consentimiento)
    if datos.acepta_compartir_datos == bool(usuario["acepta_compartir_datos"]):
        consentimiento_en = usuario["consentimiento_en"]
    elif datos.acepta_compartir_datos:
        consentimiento_en = datetime.now(timezone.utc).isoformat()
    else:
        consentimiento_en = None

    with get_conn() as conn:
        conn.execute(
            """UPDATE usuarios
               SET nombre = ?, linkedin_url = ?, acepta_compartir_datos = ?, consentimiento_en = ?
               WHERE id = ?""",
            (nombre, linkedin, int(datos.acepta_compartir_datos), consentimiento_en, usuario["id"]),
        )
        fila = conn.execute("SELECT * FROM usuarios WHERE id = ?", (usuario["id"],)).fetchone()
    return datos_publicos(fila)


# ENDPOINT DE CERRAR SESIÓN
@app.post("/auth/logout")
def cerrar_sesion(
    credenciales: Optional[HTTPAuthorizationCredentials] = Depends(esquema_bearer)
):
    if credenciales is None:
        raise HTTPException(
            status_code=401,
            detail="Falta el token de sesión."
        )

    token = credenciales.credentials.strip()

    with get_conn() as conn:
        resultado = conn.execute(
            "DELETE FROM sesiones WHERE token_hash = ?",
            (hash_token(token),)
        )

    if resultado.rowcount == 0:
        raise HTTPException(
            status_code=401,
            detail="Sesión no válida o caducada."
        )

    return {"mensaje": "Sesión cerrada correctamente."}

# ----------------------------------------------------------------------------------------------------
# BIBLIOTECA DE IMÁGENES SPHEREx

# Carpeta donde está main.py: todas las rutas se calculan desde aquí,
# así la API funciona aunque la arranques desde otra carpeta
BASE = Path(__file__).resolve().parent

# Carpeta con las imágenes (spherex-images/timelapse/... y spherex-images/overview/...).
# Se puede cambiar con la variable de entorno WIKIVERSE_IMAGES.
IMG_DIR = Path(os.environ.get("WIKIVERSE_IMAGES", BASE / "spherex-images"))

# Archivo con el catálogo (objetivos y visitas). Solo se lee al crear la base de datos.
CATALOGO_JSON = BASE / "catalogo.json"

BANDAS = {"D1", "D2", "D3", "D4", "D5", "D6"}   # los 6 canales espectrales de SPHEREx


def sembrar_catalogo():
    """Si la tabla de objetivos está vacía, la rellena con catalogo.json.
    Si ya tiene datos no toca nada (así no se duplican filas al reiniciar)."""
    with get_conn() as conn:
        if conn.execute("SELECT COUNT(*) FROM objetivos").fetchone()[0] > 0:
            return
        if not CATALOGO_JSON.is_file():
            print(f"AVISO: no encuentro {CATALOGO_JSON.name}; la biblioteca estará vacía.")
            return
        catalogo = json.loads(CATALOGO_JSON.read_text(encoding="utf-8"))
        for orden, o in enumerate(catalogo):
            ov = o["overview"]
            conn.execute(
                """INSERT INTO objetivos
                   (key, orden, nombre, tipo, ra_deg, dec_deg, overview_imagen,
                    overview_survey, overview_banda, overview_campo, overview_fuente)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (o["key"], orden, o["name"], o["kind"], o["ra"], o["dec"], ov["image"],
                 ov.get("survey"), ov.get("band"), ov.get("field"), ov.get("source")),
            )
            for banda, contenido in o["bands"].items():
                for v in contenido["visits"]:
                    conn.execute(
                        """INSERT INTO visitas
                           (objetivo_key, banda, fecha, hora, mjd, imagen, obs_id, coleccion,
                            fuente, epoca, grupo, grupo_frame, dias_grupo_previo)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (o["key"], banda, v["date"], v["time"], v["mjd"], v["image"], v["obsId"],
                         v["collection"], v["source"], v.get("epoch"), v["group"],
                         v["groupFrame"], v["daysSincePreviousGroup"]),
                    )
        print(f"Catálogo cargado: {len(catalogo)} objetivos.")


sembrar_catalogo()


def construir_catalogo(conn) -> list:
    """Lee la base de datos y devuelve los objetivos con la misma forma que usa la web:
    objetivo -> bands -> D1..D6 -> visits (ordenadas por fecha)."""
    resultado = []
    for o in conn.execute("SELECT * FROM objetivos ORDER BY orden"):
        bandas = {}
        for v in conn.execute(
            "SELECT * FROM visitas WHERE objetivo_key = ? ORDER BY banda, id", (o["key"],)
        ):
            bandas.setdefault(v["banda"], {"visits": []})["visits"].append({
                "date": v["fecha"],
                "time": v["hora"],
                "mjd": v["mjd"],
                "image": v["imagen"],
                "obsId": v["obs_id"],
                "collection": v["coleccion"],
                "source": v["fuente"],
                "epoch": v["epoca"],
                "group": v["grupo"],
                "groupFrame": v["grupo_frame"],
                "daysSincePreviousGroup": v["dias_grupo_previo"],
            })
        resultado.append({
            "key": o["key"],
            "name": o["nombre"],
            "kind": o["tipo"],
            "ra": o["ra_deg"],
            "dec": o["dec_deg"],
            "bands": bandas,
            "overview": {
                "image": o["overview_imagen"],
                "survey": o["overview_survey"],
                "band": o["overview_banda"],
                "field": o["overview_campo"],
                "source": o["overview_fuente"],
            },
        })
    return resultado


@app.get("/objetivos")
def listar_objetivos():
    """Devuelve toda la biblioteca: cada objetivo con sus 6 bandas y todas sus exposiciones.
    Las rutas de imagen (campo "image") se piden después a /spherex-images/..."""
    with get_conn() as conn:
        return construir_catalogo(conn)


@app.get("/objetivos/cercano")
def objetivo_cercano(
    ra: float = Query(ge=0, le=360),        # ascensión recta, 0° a 360°
    dec: float = Query(ge=-90, le=90),      # declinación, -90° a +90°
):
    """Busca el objetivo de la biblioteca más cercano a unas coordenadas (J2000)."""
    r = math.pi / 180
    with get_conn() as conn:
        filas = conn.execute("SELECT key, nombre, ra_deg, dec_deg FROM objetivos").fetchall()
    if not filas:
        raise HTTPException(status_code=404, detail="La biblioteca está vacía.")

    mejor, mejor_dist = None, None
    for f in filas:
        # Distancia angular entre dos puntos de la esfera celeste (fórmula del coseno esférico)
        coseno = (math.sin(dec * r) * math.sin(f["dec_deg"] * r)
                  + math.cos(dec * r) * math.cos(f["dec_deg"] * r)
                  * math.cos((f["ra_deg"] - ra) * r))
        dist = math.degrees(math.acos(max(-1.0, min(1.0, coseno))))
        if mejor_dist is None or dist < mejor_dist:
            mejor, mejor_dist = f, dist

    return {"key": mejor["key"], "nombre": mejor["nombre"],
            "separacion_deg": round(mejor_dist, 3)}


@app.get("/biblioteca/estado")
def estado_biblioteca():
    """Comprueba cuántas imágenes del catálogo existen de verdad en la carpeta spherex-images.
    Útil para saber por qué una imagen no carga."""
    with get_conn() as conn:
        rutas = [f["imagen"] for f in conn.execute("SELECT imagen FROM visitas")]
        rutas += [f["overview_imagen"] for f in conn.execute("SELECT overview_imagen FROM objetivos")]
        n_obj = conn.execute("SELECT COUNT(*) FROM objetivos").fetchone()[0]
    # Las rutas del catálogo empiezan por "spherex-images/": se resuelven dentro de IMG_DIR
    faltan = [r for r in rutas if not (IMG_DIR / r.split("/", 1)[1]).is_file()]
    return {
        "carpeta_imagenes": str(IMG_DIR),
        "carpeta_existe": IMG_DIR.is_dir(),
        "objetivos": n_obj,
        "imagenes_en_catalogo": len(rutas),
        "imagenes_encontradas": len(rutas) - len(faltan),
        "imagenes_que_faltan": faltan[:20],   # solo las 20 primeras, para no devolver una lista enorme
    }


# ANOMALÍAS: REPORTES DE USUARIOS (todos exigen sesión)

class AnomaliaIn(BaseModel):
    """Datos que envía el comparador de píxeles al pulsar "Report anomaly".
    El servidor no se fía de los datos del objetivo: comprueba contra la biblioteca."""
    objeto: str = Field(max_length=60)              # "key" del objetivo, p. ej. "barnards"
    banda: str = Field(max_length=2)                # D1 ... D6
    obs_a: str = Field(max_length=80)               # exposición A
    obs_b: str = Field(max_length=80)               # exposición B
    offset_px: float
    offset_arcsec: float
    offset_sigma: float
    rel_brightness_change: float
    brightness_sigma: float
    n_refs: int = Field(ge=0, le=1000)
    method: str = Field(default="browser-pixel-comparator-v1", max_length=60)
    nota: Optional[str] = Field(default=None, max_length=500)


@app.post("/anomalias", status_code=201)
def reportar_anomalia(datos: AnomaliaIn, usuario=Depends(usuario_actual)):
    """Guarda un candidato a anomalía enviado por el usuario con la sesión iniciada."""
    if datos.banda not in BANDAS:
        raise HTTPException(status_code=422, detail="La banda debe ser D1, D2, D3, D4, D5 o D6.")
    if datos.obs_a == datos.obs_b:
        raise HTTPException(status_code=422, detail="Hay que comparar dos exposiciones distintas.")

    with get_conn() as conn:
        # Las dos exposiciones tienen que existir en la biblioteca, para ese objetivo y banda
        fechas = []
        for obs in (datos.obs_a, datos.obs_b):
            fila = conn.execute(
                "SELECT fecha FROM visitas WHERE objetivo_key = ? AND banda = ? AND obs_id = ?",
                (datos.objeto, datos.banda, obs),
            ).fetchone()
            if fila is None:
                raise HTTPException(
                    status_code=422,
                    detail="Esa exposición no existe en la biblioteca para ese objetivo y banda.",
                )
            fechas.append(fila["fecha"])

        try:
            cur = conn.execute(
                """INSERT INTO anomalias
                   (usuario_id, objetivo_key, banda, obs_a, obs_b, fecha_a, fecha_b,
                    offset_px, offset_arcsec, offset_sigma, cambio_brillo, brillo_sigma,
                    n_refs, metodo, nota)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (usuario["id"], datos.objeto, datos.banda, datos.obs_a, datos.obs_b,
                 fechas[0], fechas[1], datos.offset_px, datos.offset_arcsec, datos.offset_sigma,
                 datos.rel_brightness_change, datos.brightness_sigma, datos.n_refs,
                 datos.method, (datos.nota or "").strip() or None),
            )
        except sqlite3.IntegrityError:
            # Salta por la restricción UNIQUE de la tabla: ese par ya lo reportó este usuario
            raise HTTPException(status_code=409, detail="Ya reportaste este par de exposiciones.")

    # El estado siempre empieza como "unverified_candidate": lo decide el servidor, no la web
    return {"id": cur.lastrowid, "estado": "unverified_candidate"}


@app.get("/anomalias/mias")
def mis_anomalias(usuario=Depends(usuario_actual)):
    """Lista los reportes del usuario con la sesión iniciada (los más recientes primero)."""
    with get_conn() as conn:
        filas = conn.execute(
            """SELECT a.*, o.nombre AS objeto_nombre
               FROM anomalias a JOIN objetivos o ON o.key = a.objetivo_key
               WHERE a.usuario_id = ? ORDER BY a.id DESC""",
            (usuario["id"],),
        ).fetchall()
    return {"total": len(filas), "anomalias": [dict(f) for f in filas]}


# ----------------------------------------------------------------------------------------------------
# ESTOS ENDPOINTS SON SOLO PARA PRUEBAS EN SWAGGER. EN UNA APLICACIÓN REAL, NO SE DEBERÍAN EXPONER.

# ENDPOINTS DE LISTAR USUARIOS
@app.get("/usuarios")
def listar_usuarios():
    """
    Devuelve todos los usuarios registrados.
    Solo para pruebas en Swagger.
    """
    with get_conn() as conn:
        filas = conn.execute(
            """
            SELECT *
            FROM usuarios
            ORDER BY id
            """
        ).fetchall()

    return [datos_publicos(fila) for fila in filas]

# ENDPOINT DE BORRAR USUARIO
@app.delete("/usuarios/{usuario_id}")
def eliminar_usuario(usuario_id: int):
    """
    Elimina un usuario por su id.
    Solo para pruebas en Swagger.
    """

    with get_conn() as conn:
        resultado = conn.execute(
            "DELETE FROM usuarios WHERE id = ?",
            (usuario_id,)
        )

    if resultado.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Usuario no encontrado."
        )

    return {
        "mensaje": f"Usuario {usuario_id} eliminado correctamente."
    }


# IMÁGENES Y PÁGINA WEB
# Las rutas fijas (/objetivos, /auth, ...) se definen antes, así que no chocan con esto.

# Sirve la carpeta de imágenes en /spherex-images/... (check_dir=False: la API arranca
# aunque la carpeta aún no exista, y /biblioteca/estado te dirá qué falta)
app.mount("/spherex-images", StaticFiles(directory=IMG_DIR, check_dir=False), name="imagenes")


@app.get("/", include_in_schema=False)
def pagina_principal():
    """Devuelve la web (index.html) para poder abrirla en http://127.0.0.1:8000/
    Así la página y la API comparten origen y no hace falta configurar nada más."""
    ruta = BASE / "index.html"
    if not ruta.is_file():
        raise HTTPException(status_code=404, detail="No encuentro index.html junto a main.py.")
    return FileResponse(ruta)
