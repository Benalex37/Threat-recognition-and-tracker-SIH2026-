import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.api.routes import router
from app.config import ensure_data_dirs, load_config, STATIC_DIR
from app._version import __version__

app = FastAPI(title="Email Threat Detection Local Engine", version=__version__)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

app.include_router(router)


@app.on_event("startup")
async def startup():
    ensure_data_dirs()
    config = load_config()
    from app.services.storage import atomic_write_json
    from app.config import CONFIG_PATH, ADAPTER_MANIFEST_PATH
    if not CONFIG_PATH.exists():
        atomic_write_json(CONFIG_PATH, config)
    if not ADAPTER_MANIFEST_PATH.exists():
        atomic_write_json(ADAPTER_MANIFEST_PATH, {"adapters": []})

    # Cases written before the evidence ledger existed still need blocks, or
    # verification would report them as unsealed forever.
    from app.services import ledger
    from app.services.storage import read_all_cases
    sealed = ledger.backfill(read_all_cases())
    if sealed:
        print(f"  Evidence ledger: sealed {sealed} existing case(s)")