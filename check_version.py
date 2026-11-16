import sys, json
sys.path.insert(0, r"C:\Users\pshte\OneDrive\Desktop\sih\desktop-app")

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

r = client.get("/")
print("GET / ->", r.status_code, r.json())

r = client.get("/api/config")
print("GET /api/config ->", r.status_code, r.json().get("version"))