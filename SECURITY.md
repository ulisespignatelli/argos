# Seguridad

## Reportar una vulnerabilidad

Si encontrás una falla de seguridad en ARGOS, no abras un issue público: escribime por privado
(los datos de contacto están en mi perfil de GitHub). Respondo dentro de las 72 horas.

## Modelo de amenazas

ARGOS procesa datos de fuentes externas y los muestra en un navegador. Estas son las amenazas
consideradas y cómo se mitigan:

| Amenaza | Ejemplo | Mitigación |
|---|---|---|
| Contenido malicioso en las fuentes | Un indicador con `<script>` o un enlace `javascript:` | Validación con Pydantic al entrar; en la interfaz todo se muestra con `textContent` y solo se aceptan enlaces `http(s)` |
| Clic accidental en un indicador | Abrir una URL de malware desde el panel | Indicadores desactivados (`hxxp://1[.]2[.]3[.]4`) |
| Inyección de fórmulas | Un valor `=cmd|...` en el CSV exportado | Los valores que empiezan con `=`, `+`, `-` o `@` se neutralizan |
| Inyección SQL | Valores externos en consultas | Todas las consultas usan parámetros |
| Fuga de claves | La clave de abuse.ch en el repositorio o en el navegador | Clave solo en `backend/.env` (en `.gitignore`), nunca enviada al frontend; gitleaks en CI |
| Abuso de la API | Un cliente que satura el servidor | Límite de consultas por IP (token bucket) |
| Clickjacking y XSS | La interfaz embebida en otro sitio | CSP, `X-Frame-Options: DENY` y `frame-ancestors 'none'` |
| Dependencias vulnerables | Una librería con una CVE | `pip-audit` y `npm audit` en CI, Dependabot semanal |
| Escalada en el contenedor | Un fallo que permite ejecutar código | Usuario sin privilegios, sistema de archivos de solo lectura, `no-new-privileges` |
| Falsas acusaciones en la demo | Mostrar una IP real como maliciosa | El modo demo usa solo rangos de documentación (RFC 5737) y dominios `.example` (RFC 2606) |

## Privacidad

ARGOS no procesa datos personales. Solo se envían a ip-api direcciones IP públicas que ya son
indicadores públicos de amenazas, y cada una se consulta una única vez gracias a la caché.

## Fuera de alcance

ARGOS no expone autenticación porque está pensado para uso local o detrás de una red privada.
Para publicarlo en internet habría que agregar autenticación delante (por ejemplo, un proxy con OAuth).
