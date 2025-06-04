#app/main


import os
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv

# 🔌 Імпорт роутерів
from kzp.secure_vote_api import router as secure_vote_router
from app.routes.admin_routes import router as admin_router

# ⬇ Завантаження змінних середовища
load_dotenv()
IS_PROD = os.getenv("IS_PROD", "False") == "True"
DOMAIN = os.getenv("DOMAIN", "https://your-domain.com")
PORT = int(os.getenv("PORT", 8000))

# 🛠 Перевірка директорії статичних файлів
if not os.path.exists("static"):
    os.makedirs("static")

#  Ініціалізація FastAPI
app = FastAPI(
    title="ІСЕГ — Інформаційна Система Електронного Голосування",
    version="1.0.0",
    description="Система для проведення захищених електронних засідань із шифруванням та підписом бюлетенів"
)

#  CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if not IS_PROD else [DOMAIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Статичні файли
app.mount("/static", StaticFiles(directory="static"), name="static")

#  Ініціалізація бази даних
from db.database import init_db
init_db()

#  Роутери
app.include_router(secure_vote_router, prefix="/secure", tags=["Захист голосу"])
app.include_router(admin_router, prefix="/admin", tags=["Адмін"])

#  Головна сторінка
@app.get("/", response_class=HTMLResponse)
def read_root():
    return FileResponse("static/index.html")
