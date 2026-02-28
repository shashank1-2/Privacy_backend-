from motor.motor_asyncio import AsyncIOMotorGridFSBucket
from app.database import db
from bson import ObjectId
import io


async def get_bucket() -> AsyncIOMotorGridFSBucket:
    return AsyncIOMotorGridFSBucket(db)


async def upload_file(file_data: bytes, filename: str, mime_type: str, owner_id: str) -> str:
    bucket = await get_bucket()
    gridfs_id = await bucket.upload_from_stream(
        filename,
        io.BytesIO(file_data),
        metadata={"owner_id": owner_id, "mime_type": mime_type},
    )
    return str(gridfs_id)


async def download_file(gridfs_id: str) -> tuple:
    bucket = await get_bucket()
    stream = await bucket.open_download_stream(ObjectId(gridfs_id))
    data = await stream.read()
    filename = stream.filename
    mime_type = (
        stream.metadata.get("mime_type", "application/octet-stream")
        if stream.metadata
        else "application/octet-stream"
    )
    return (data, filename, mime_type)


async def delete_file_from_gridfs(gridfs_id: str) -> bool:
    bucket = await get_bucket()
    try:
        await bucket.delete(ObjectId(gridfs_id))
        return True
    except Exception:
        return False
