from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
#load env
from dotenv import load_dotenv
load_dotenv()
# SQLALCHEMY_DATABASE_URL='sqlite:///cyber.db'
# engine=create_engine(SQLALCHEMY_DATABASE_URL,connect_args={"check_same_thread":False})
USER = os.getenv('POSTGRES_USER')
PASS = os.getenv('POSTGRES_PASS')
PORT = os.getenv('POSTGRES_PORT')
DB = os.getenv('POSTGRES_DB')
SQLALCHEMY_DATABASE_URL = f'postgresql://{USER}:{PASS}@localhost:{PORT}/{USER}'
engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal=sessionmaker(bind=engine,autocommit=False,autoflush=False)

Base=declarative_base()

def get_db():
    db=SessionLocal()
    try:
        yield db
    finally:
        db.close()

                