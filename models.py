from sqlalchemy import Column, Integer, String, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    blocked_sites = relationship("BlockedSite", back_populates="user")

class BlockedSite(Base):
    __tablename__ = "blocked_sites"
    id = Column(Integer, primary_key=True, index=True)
    site = Column(String, nullable=False)
    ai_suggested = Column(Boolean, default=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship("User", back_populates="blocked_sites")
