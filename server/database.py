import os
import time
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

SERVER_DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "server"
SERVER_DATA_DIR.mkdir(parents=True, exist_ok=True)

SERVER_DB_PATH = SERVER_DATA_DIR / "aegis_central.db"
SQLALCHEMY_DATABASE_URL = f"sqlite:///{SERVER_DB_PATH}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
