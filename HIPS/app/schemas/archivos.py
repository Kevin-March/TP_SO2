from pydantic import BaseModel

class Archivos(BaseModel):
    id: int
    archivo: str
    hash: str
    fecha: str

class ArchivosCreate(BaseModel):
    archivo: str
    hash: str