# Arquitectura

## Visión general

ARGOS son dos aplicaciones independientes que solo comparten un contrato de datos (`Entity`):

```
                ┌──────────────────────────── backend (Python) ───────────────────────────┐
ThreatFox ──┐   │                                                                          │
URLhaus ────┤   │                  GeoIP + caché                                           │
CISA KEV ───┼──►│ recolectores ─► enriquecimiento ─► caché ─┬─► WebSocket ──────────────────┼──► navegador
ransomware  ┘   │ (adaptadores)   MITRE ATT&CK (local)       ├─► motor de alertas ─► WebSocket │
 .live          │                                            ├─► actores, matriz, informe    │
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
| `knowledge/` | Base de conocimiento local | Índice compacto de ATT&CK y MISP, versionado en el repo: sin red ni dependencia de una API externa para enriquecer. |
| `services/attack_enrichment.py` | Tubería (pipeline) | Enlaza cada indicador con software, grupos y técnicas; marca aparte la atribución directa. |
| `services/intel.py` | Consulta sobre la caché | Actores activos con relevancia ponderada por exclusividad y matriz ATT&CK dinámica. |
| `services/correlation.py` | Consulta sobre la caché | El pivote no consulta fuentes externas: responde en milisegundos y no gasta cuota. |
| `services/hub.py` | Publicación y suscripción | Los cambios se empujan a los navegadores; nadie pregunta cada tanto. |
| `storage/` | Repositorio | SQLite detrás de interfaces chicas; se puede pasar a Postgres sin tocar el resto. |
| `main.py` | Raíz de composición | El único lugar donde se crean y conectan las piezas. Por eso cada una se prueba por separado. |

## Frontend

| Pieza | Patrón | Por qué |
|---|---|---|
| `state/store.ts` | Flujo unidireccional | El WebSocket y las acciones del usuario actualizan el estado; las vistas solo lo leen. |
| `layers/` | Plugins con clase base | `PointLayer` resuelve lo común; cada capa define su estilo y su ficha. |
| `ui/investigation.ts` | Navegación por migas | Cada pivote es un paso; se puede volver a cualquiera. Si el paso es un actor, suma su ficha. |
| `ui/topbar.ts` | Vista derivada del estado | Los tres contadores (ataques, CVE, infraestructura) se calculan del estado, nunca se mezclan. |
| `ui/overlays.ts` | Ventanas bajo demanda | Listado de actores y matriz ATT&CK: se piden a la API solo al abrirse. |

## Decisiones de análisis

- **Atribución nunca inventada:** el país de origen solo se muestra si el propio grupo lo tiene en MISP. Que un
  grupo use una herramienta no lo convierte en dueño de cada servidor de esa herramienta.
- **Exclusividad como peso:** la relevancia de un actor suma 1/N por cada indicador de un software que usan N
  grupos. Sin esto, cualquier ranking lo encabezan quienes usan Cobalt Strike.
- **Reivindicado no es confirmado:** las víctimas de ransomware se rotulan como reivindicadas por el grupo.
- **Noticias sin IA:** los eventos se arman con reglas transparentes (regex de CVE, diccionario de ATT&CK,
  nombres de países, palabras clave). Es gratis, reproducible y cada decisión queda anotada en `reasons`.
  Un nombre de una sola palabra que también es palabra común ("Royal", "Play") solo cuenta si aparece
  cerca de "ransomware", "group", "malware", etc.
- **Verificado tiene una definición:** fuente oficial, 2 o más medios distintos, o CVE en el catálogo KEV.
  Lo demás se muestra como "1 fuente".
- **Cada tipo de evento en su lugar:** las vulnerabilidades no se ubican en el mapa, y los avisos no se cuentan
  como ataques.

## Decisiones

- **Python y no Go para el backend:** el trabajo es esperar respuestas de red, que `asyncio` resuelve bien, y el ecosistema de seguridad está en Python.
- **SQLite y no Postgres por ahora:** cero instalación para quien clona el repo. La interfaz de repositorio deja la puerta abierta.
- **TypeScript sin framework:** la interfaz es chica y así hay menos dependencias que auditar.
- **Correlación en memoria:** con miles de indicadores alcanza y sobra. Con millones, el paso natural es un grafo en base de datos.
