# Pavos Updater

Programa de línea de comandos que actualiza los pavos (V-Bucks) de todas las
cuentas de Fortnite en la base de datos, consultando la API de Epic Games.

## Configuración

Toma la configuración del entorno (o de un archivo `.env` en el directorio desde
el que se ejecuta), igual que el servidor principal:

| Variable      | Requerida | Notas                                                        |
|---------------|-----------|-------------------------------------------------------------|
| `DB_HOST`     | sí        |                                                            |
| `DB_PORT`     | sí        |                                                            |
| `DB_USER`     | sí        |                                                            |
| `DB_PASSWORD` | sí        |                                                            |
| `DB_NAME`     | sí        |                                                            |
| `DB_SSLMODE`  | no        | Por defecto `disable`. Usar `require` si te conectas por internet. |
| `SECRET_KEY`  | sí        | Necesaria porque comparte el paquete de config del servidor. |
| `EPIC_CLIENT` / `EPIC_SECRET` | sí | Credenciales de la app de Epic para refrescar tokens. |

> Las credenciales ya no están hardcodeadas en el código.

## Uso

Desde la raíz del repo:

```bash
go build -o pavos_updater.exe ./pavos_updater
./pavos_updater.exe
```

## Funcionalidad

- Se conecta a PostgreSQL con las variables de entorno.
- Obtiene todas las cuentas de juego.
- Para cada cuenta actualiza los pavos consultando la API de Epic Games.
- Imprime un resumen con cuentas actualizadas y errores.
