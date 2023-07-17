from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from app.db.base_class import BaseWithDatetime
# create model for table archivos_hash
class ArchivosHash(BaseWithDatetime):
    __tablename__ = "archivos_hash"
    id = Column(Integer, primary_key=True, index=True)
    archivo = Column(String, nullable=False)
    hash = Column(String, nullable=False)