from motor.motor_asyncio import AsyncIOMotorClient
from config import MONGODB_URI

client: AsyncIOMotorClient = None
db = None
db_connected = False


async def connect_db():
    global client, db, db_connected
    if not MONGODB_URI:
        print("⚠️  No MONGODB_URI set — running without database (scans won't be saved)")
        return

    try:
        client = AsyncIOMotorClient(
            MONGODB_URI,
            serverSelectionTimeoutMS=15000,
            connectTimeoutMS=10000,
            socketTimeoutMS=20000,
            retryWrites=True,
            retryReads=True,
        )
        # Verify connection actually works
        await client.admin.command("ping")
        db = client.phishguard
        db_connected = True

        # Create indexes
        await db.scans.create_index("created_at")
        await db.scans.create_index("content_hash")
        await db.scans.create_index("risk_score")
        await db.scans.create_index([("user_id", 1), ("created_at", -1)])
        await db.users.create_index("email", unique=True)
        await db.sessions.create_index("token", unique=True)
        await db.sessions.create_index("user_id")
        print("✅ Connected to MongoDB Atlas")
    except Exception as e:
        print(f"⚠️  MongoDB connection failed: {e}")
        print("   App will still work — scans won't be saved to history.")
        db_connected = False


async def close_db():
    global client
    if client:
        client.close()
        print("🔌 MongoDB connection closed")


def get_db():
    if db_connected and db is not None:
        return db
    return None


def is_db_connected():
    return db_connected
