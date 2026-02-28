import os
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorGridFSBucket
from dotenv import load_dotenv

load_dotenv()

MONGO_URL = os.environ.get("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = "privacyvault_db"

motor_client = AsyncIOMotorClient(MONGO_URL)
db = motor_client[DB_NAME]

users_col = db["users"]
files_col = db["shared_files"]
links_col = db["share_links"]
audit_col = db["audit_logs"]
devices_col = db["device_records"]


async def get_gridfs() -> AsyncIOMotorGridFSBucket:
    return AsyncIOMotorGridFSBucket(db)


async def init_db():
    await users_col.create_index("email", unique=True)
    await links_col.create_index("token", unique=True)
    await links_col.create_index("created_by")
    await links_col.create_index("status")
    await audit_col.create_index([("timestamp", -1)])
    await audit_col.create_index("event_type")
    await audit_col.create_index("user_id")
    await files_col.create_index("owner_id")
    await files_col.create_index([("uploaded_at", -1)])
    await devices_col.create_index("share_link_id")
    print("[DB] MongoDB indexes created for privacyvault_db")

    # TODO Remove this cleanup block after first successful deployment.
    res = await audit_col.delete_many({
        "$or": [
            {"user_id": {"$exists": False}},
            {"user_id": None},
            {"user_id": ""},
            {"user_id": "anonymous"},
            {"user_id": "public"},
            {"user_id": "undefined"},
            {"user_id": "null"}
        ]
    })
    print(f"[DB] Cleared {res.deleted_count} invalid audit logs")
