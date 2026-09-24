import fastapi

from .shelfcat import telemetry
from .shelfcat.api import router as shelfcat_router

app = fastapi.FastAPI(
    title="ShelfCat Truth API",
    description="AI proposes. CBN transports. GPU enriches. Rust enforces. Only the gate writes truth.",
    version="1.0.0",
)
app.include_router(shelfcat_router)
telemetry.configure(app)


@app.get("/sample")
async def index():
    return {
        "info": "Try /hello/Shivani for parameterized route.",
    }


@app.get("/hello/{name}")
async def get_name(name: str):
    return {
        "name": name,
    }
