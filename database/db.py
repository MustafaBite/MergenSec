# database/db.py

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from dotenv import load_dotenv
from database.models import Base

# pulling config from .env
load_dotenv()

# default to sqlite if the env variable isnt set
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///mergensec.db")

engine = create_engine(DATABASE_URL, echo=False)
SessionLocal = sessionmaker(bind=engine)


def init_db() -> None:
    """run this to create the tables in the db"""
    Base.metadata.create_all(bind=engine)
    print("✅ database initialized successfully")


def get_session() -> Session:
    """helper to get a database session"""
    return SessionLocal()