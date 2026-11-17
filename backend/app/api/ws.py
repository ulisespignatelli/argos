from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()


@router.websocket("/ws")
async def live(ws: WebSocket):
    hub, cache, alerts = ws.app.state.hub, ws.app.state.cache, ws.app.state.alerts
    await hub.connect(ws)
    try:
        # Al conectarse, el cliente recibe el estado completo y las alertas recientes; despues, solo cambios.
        for snap in cache.all():
            await ws.send_json({"type": "snapshot", "snapshot": snap.model_dump(mode="json")})
        recent = await alerts.recent(50)
        await ws.send_json({"type": "alerts", "alerts": [a.model_dump(mode="json") for a in recent]})
        while True:
            await ws.receive_text()   # mantiene viva la conexion; el cliente manda pings
    except WebSocketDisconnect:
        pass
    finally:
        hub.disconnect(ws)
