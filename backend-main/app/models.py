from .database import Base 
from sqlalchemy import Column, Integer, String, ForeignKey, JSON
from sqlalchemy.orm import relationship

class UserCredentials(Base):
    __tablename__ = 'user_credentials'
    email = Column(String, primary_key=True)
    password = Column(String)

    password_data = relationship("PasswordData", back_populates="user")

class PasswordData(Base):
    __tablename__ = 'password_data'
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String, ForeignKey('user_credentials.email'))
    tag_password = Column(JSON)

    user = relationship("UserCredentials", back_populates="password_data")
