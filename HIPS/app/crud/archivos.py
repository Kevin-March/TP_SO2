"""Crud for archivos."""

from app.crud.base import CRUDBase
from app.models import archivos_hash
from app.schemas.archivos import *


class CRUDArchivos(CRUDBase[archivos_hash.ArchivosHash, ArchivosCreate, ArchivosCreate]):
    def get_by_name(self, db, name: str) -> archivos_hash.ArchivosHash:
        return db.query(self.model).filter(self.model.archivo == name).first()


crud_archivos = CRUDArchivos(archivos_hash.ArchivosHash)
