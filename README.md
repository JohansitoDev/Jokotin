# Jokotin

Jokotin es un lenguaje sencillo para crear APIs con sintaxis inspirada en Ruby.
Escribe rutas en archivos `.jok` y ejecútalas con el runtime independiente
incluido. **No necesitas instalar Go**.

## Crear una API

Estructura mínima:

```text
mi-api/
  main.jok
  routes/
    users.jok
```

`main.jok` carga rutas desde archivos relativos, conecta una base de datos
SQLite persistente y arranca el servidor:

```ruby
require "./routes/users"

db connect "sqlite:./data/api.db"
server 3000
```

`routes/users.jok` define endpoints y respuestas JSON:

```ruby
api get "/users" do
  users = db.all("users")
  return users json
end

api post "/users" do
  user = req.body
  user.id = uuid.generate()
  db.insert("users", user)
  return { message: "Created", id: user.id } status 201
end

api get "/users/:id" do
  user = db.find("users", id: req.params.id)
  if user
    return user json
  else
    return { error: "Not found" } status 404
  end
end
```

También puedes definir endpoints `PUT`, `PATCH`, `DELETE`, `OPTIONS`, `HEAD`
y otros métodos HTTP. Dentro de una ruta están disponibles `req.body`,
`req.params.id`, `req.query.page`, `req.headers.authorization`, `req.method`
y `req.path`. Usa `require "./routes/users"` para enlazar archivos; la ruta es
relativa al archivo que la importa y la extensión `.jok` es opcional.

## Base de datos

SQLite viene incluido y guarda los datos en un archivo. La ruta es relativa a
`main.jok`; Jokotin crea la carpeta y el archivo automáticamente:

```ruby
db connect "sqlite:./data/api.db"
```

Para PostgreSQL, configura `DATABASE_URL` y no pongas credenciales en el código:

```ruby
db connect env "DATABASE_URL"
```

En PowerShell, antes de ejecutar el backend, define la URL de tu instancia:

```powershell
$env:DATABASE_URL = "postgres://usuario:clave@localhost:5432/mi_base?sslmode=disable"
```

Ambos motores persisten los registros. Jokotin crea la tabla interna
`jokotin_records` automáticamente y expone las operaciones `db.all`, `db.find`,
`db.insert`, `db.update` y `db.delete`.

## Ejecutar y probar

En Windows x64, desde la carpeta que contiene `jok.exe`:

```powershell
.\jok.exe run .\mi-api\main.jok
```

Prueba los endpoints:

```powershell
Invoke-RestMethod http://localhost:3000/users
Invoke-RestMethod -Method Post `
  -Uri http://localhost:3000/users `
  -ContentType "application/json" `
  -Body '{"name":"Ada"}'
```

La documentación **OpenAPI y Swagger UI se generan automáticamente** para las
rutas del proyecto:

- Swagger UI: <http://localhost:3000/docs>
- Documento OpenAPI: <http://localhost:3000/swagger.json>

Si una ruta usa `jwt.verify`, aparece protegida con autenticación Bearer en
Swagger. Los endpoints automáticos `/docs` y `/swagger.json` están reservados.
Swagger UI obtiene su interfaz desde un CDN; el documento OpenAPI se sirve
directamente desde Jokotin.

## Contraseñas y JWT

`hash.make(password)` produce un hash PBKDF2-SHA-256 con salt aleatorio;
`hash.check(password, hash_guardado)` compara la contraseña. Los campos
`password` y los que empiezan por `_` se excluyen de respuestas JSON.
`jwt.create(id)` firma un token HS256 válido durante una hora.
`jwt.verify(req.headers.authorization)` valida el token Bearer.

Cuando la aplicación usa JWT, define una clave aleatoria de al menos 32
caracteres en `JOKOTIN_JWT_SECRET` antes de iniciarla:

```powershell
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$rng.Dispose()
$env:JOKOTIN_JWT_SECRET = [Convert]::ToBase64String($bytes)
.\jok.exe run .\mi-api\main.jok
```

## GitHub y VS Code

La extensión de VS Code resalta `.jok` y añade snippets. Para ver esos colores
en GitHub, `.gitattributes` asocia los archivos `.jok` con el resaltador Ruby.
GitHub decide el nombre de la barra **Languages** usando su lista central de
lenguajes: un repositorio no puede registrar allí un nombre nuevo. Hasta que
GitHub Linguist añada Jokotin oficialmente, GitHub los contará como Ruby; VS
Code sí los identifica como Jokotin.

Para desarrollar con la extensión, abre el proyecto en VS Code, presiona `F5`
y abre cualquier `.jok` en la ventana de desarrollo. Para ejecutar la API solo
necesitas `jok.exe`; no necesitas Go, Python ni Node.js.
