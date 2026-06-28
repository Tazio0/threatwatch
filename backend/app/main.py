from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend.app.services.geoip_service import ensure_geoip_databases

@asynccontextmanager
async def lifespan(app: FastAPI):
    ensure_geoip_databases()
    yield


app = FastAPI(lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "ok"}
