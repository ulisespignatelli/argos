# Arquitectura

## Visión general

ARGOS son dos aplicaciones independientes que solo comparten un contrato de datos (`Entity`):

```
                ┌──────────────────────────── backend (Python) ───────────────────────────┐
ThreatFox ──┐   │                                                                          │
URLhaus ────┼──►│ recolectores ─► enriquecimiento ─► caché ─┬─► WebSocket ──────────────────┼──► navegador
CISA KEV ───┘   │ (adaptadores)   (GeoIP + caché)            ├─► motor de alertas ─► WebSocket │
                │                                            ├─► historial (SQLite)          │
                │                                            └─► REST: capas, pivote,        │
                │                                                alertas, exportación        │
                └──────────────────────────────────────────────────────────────────────────┘
```

## Backend

| Pieza | Patrón | Por qué |
|---|---|---|
| `collectors/` | Puertos y adaptadores | Cada fuente traduce su formato al modelo común. Sumar una fuente es agregar un archivo. |
| `geolocation/` | Puertos y adaptadores | El proveedor de GeoIP es intercambiable (ip-api, demo, o MaxMind en el futuro). |
| `services/scheduler.py` | Productor y consumidor | Cada fuente corre en su propio ciclo con espera creciente ante errores. Una fuente caída no frena a las demás y conserva su último dato bueno. |
| `services/enrichment.py` | Tubería (pipeline) | Pasos que agregan información entre la fuente y la caché, sin que la fuente lo sepa. |
| `services/alerts.py` | Observador | Escucha cada actualización y la compara con la anterior. |
| `services/correlation.py` | Consulta sobre la caché | El pivote no consulta fuentes externas: responde en milisegundos y no gasta cuota. |
| `services/hub.py` | Publicación y suscripción | Los cambios se empujan a los navegadores; nadie pregunta cada tanto. |
| `storage/` | Repositorio | SQLite detrás de interfaces chicas; se puede pasar a Postgres sin tocar el resto. |
| `main.py` | Raíz de composición | El único lugar donde se crean y conectan las piezas. Por eso cada una se prueba por separado. |

## Frontend

| Pieza | Patrón | Por qué |
|---|---|---|
| `state/store.ts` | Flujo unidireccional | El WebSocket y las acciones del usuario actualizan el estado; las vistas solo lo leen. |
| `layers/` | Plugins con clase base | `PointLayer` resuelve lo común; cada capa define su estilo y su ficha. |
| `ui/investigation.ts` | Navegación por migas | Cada pivote es un paso; se puede volver a cualquiera. |

## Decisiones

- **Python y no Go para el backend:** el trabajo es esperar respuestas de red, que `asyncio` resuelve bien, y el ecosistema de seguridad está en Python.
- **SQLite y no Postgres por ahora:** cero instalación para quien clona el repo. La interfaz de repositorio deja la puerta abierta.
- **TypeScript sin framework:** la interfaz es chica y así hay menos dependencias que auditar.
- **Correlación en memoria:** con miles de indicadores alcanza y sobra. Con millones, el paso natural es un grafo en base de datos.
