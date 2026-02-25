from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Optional
import hashlib
import secrets

from bson import ObjectId

from config import PORT
from database import connect_db, close_db, get_db, is_db_connected
from models import AuthRequest, AuthResponse, ScanRequest, ScanResult, ScanHistory, UserInfo
from ai_service import analyze_content, compute_content_hash


@asynccontextmanager
async def lifespan(app: FastAPI):
    await connect_db()
    yield
    await close_db()


app = FastAPI(
    title="PhishGuard API",
    description="AI-powered phishing & scam detection API",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000)
    return f"{salt.hex()}${digest.hex()}"


def _verify_password(password: str, password_hash: str) -> bool:
    try:
        salt_hex, digest_hex = password_hash.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120000)
        return secrets.compare_digest(actual, expected)
    except Exception:
        return False


def _build_user_info(user_doc: dict) -> UserInfo:
    return UserInfo(
        id=str(user_doc["_id"]),
        email=user_doc["email"],
        name=user_doc.get("name"),
        created_at=user_doc.get("created_at", datetime.utcnow().isoformat()),
    )


async def _require_user(x_auth_token: Optional[str] = Header(default=None, alias="X-Auth-Token")) -> dict:
    if not x_auth_token:
        raise HTTPException(status_code=401, detail="Authentication required")

    db = get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    session = await db.sessions.find_one({"token": x_auth_token})
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    user = await db.users.find_one({"_id": session["user_id"]})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid session user")

    return user


@app.get("/")
async def root():
    return {"status": "ok", "service": "PhishGuard API", "version": "1.0.0"}


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "database": "connected" if is_db_connected() else "disconnected",
    }


@app.post("/api/auth/signup", response_model=AuthResponse)
async def signup(request: AuthRequest):
    db = get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    email = _normalize_email(request.email)
    if "@" not in email or len(email) < 5:
        raise HTTPException(status_code=400, detail="Invalid email")
    if len(request.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")

    user_doc = {
        "email": email,
        "name": request.name.strip() if request.name else None,
        "password_hash": _hash_password(request.password),
        "created_at": datetime.utcnow().isoformat(),
    }
    inserted = await db.users.insert_one(user_doc)
    user_doc["_id"] = inserted.inserted_id

    token = secrets.token_urlsafe(32)
    await db.sessions.insert_one(
        {
            "token": token,
            "user_id": inserted.inserted_id,
            "created_at": datetime.utcnow().isoformat(),
        }
    )

    return AuthResponse(token=token, user=_build_user_info(user_doc))


@app.post("/api/auth/login", response_model=AuthResponse)
async def login(request: AuthRequest):
    db = get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")

    email = _normalize_email(request.email)
    user = await db.users.find_one({"email": email})
    if not user or not _verify_password(request.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = secrets.token_urlsafe(32)
    await db.sessions.insert_one(
        {
            "token": token,
            "user_id": user["_id"],
            "created_at": datetime.utcnow().isoformat(),
        }
    )
    return AuthResponse(token=token, user=_build_user_info(user))


@app.get("/api/auth/me", response_model=UserInfo)
async def get_me(user: dict = Depends(_require_user)):
    return _build_user_info(user)


@app.post("/api/auth/logout")
async def logout(user: dict = Depends(_require_user), x_auth_token: Optional[str] = Header(default=None, alias="X-Auth-Token")):
    db = get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable")
    await db.sessions.delete_one({"token": x_auth_token, "user_id": user["_id"]})
    return {"ok": True}


@app.post("/api/scan", response_model=ScanResult)
async def scan_content(request: ScanRequest, user: dict = Depends(_require_user)):
    """Scan content for phishing/scam threats."""
    try:
        content = request.content

        if not content or len(content.strip()) < 3:
            raise HTTPException(status_code=400, detail="Content too short to analyze")

        db = get_db()
        content_hash = compute_content_hash(content)

        # Always re-analyze (no cache) to ensure latest rules apply
        # Run AI analysis
        ai_result = await analyze_content(request.content_type, content)

        # Build result
        result_data = {
            "user_id": user["_id"],
            "content_type": request.content_type,
            "content_preview": content[:200] + ("..." if len(content) > 200 else ""),
            "is_spam": ai_result["is_spam"],
            "risk_score": ai_result["risk_score"],
            "risk_level": ai_result["risk_level"],
            "verdict": ai_result["verdict"],
            "reasons": ai_result["reasons"],
            "probable_source": ai_result["probable_source"],
            "source_category": ai_result["source_category"],
            "matched_scams": [
                {
                    "title": m.get("title", "Unknown"),
                    "similarity": m.get("similarity", 0),
                    "source": m.get("source", "Unknown"),
                    "date": m.get("date")
                }
                for m in ai_result.get("matched_scam_patterns", [])
            ],
            "recommendations": ai_result["recommendations"],
            "confidence": ai_result["confidence"],
            "content_hash": content_hash,
            "created_at": datetime.utcnow().isoformat(),
        }

        # Save to MongoDB (best-effort)
        if db is not None:
            try:
                insert_result = await db.scans.insert_one(result_data.copy())
                result_data["id"] = str(insert_result.inserted_id)
            except Exception as db_err:
                print(f"DB save failed (returning result anyway): {db_err}")
                result_data["id"] = "local-" + content_hash[:12]
        else:
            result_data["id"] = "local-" + content_hash[:12]

        if "content_hash" in result_data:
            del result_data["content_hash"]
        if "user_id" in result_data:
            del result_data["user_id"]

        return ScanResult(**result_data)

    except HTTPException:
        raise
    except Exception as e:
        print(f"Scan error: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/api/history", response_model=ScanHistory)
async def get_history(page: int = 1, per_page: int = 20, user: dict = Depends(_require_user)):
    """Get scan history with pagination."""
    db = get_db()
    if db is None:
        return ScanHistory(scans=[], total=0, page=page, per_page=per_page)

    try:
        skip = (page - 1) * per_page

        user_filter = {"user_id": user["_id"]}
        total = await db.scans.count_documents(user_filter)
        cursor = db.scans.find(user_filter).sort("created_at", -1).skip(skip).limit(per_page)

        scans = []
        async for doc in cursor:
            doc["id"] = str(doc["_id"])
            del doc["_id"]
            if "content_hash" in doc:
                del doc["content_hash"]
            if "user_id" in doc:
                del doc["user_id"]
            scans.append(ScanResult(**doc))

        return ScanHistory(scans=scans, total=total, page=page, per_page=per_page)

    except Exception as e:
        print(f"History error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str, user: dict = Depends(_require_user)):
    """Get a specific scan result."""
    try:
        db = get_db()
        if db is None:
            raise HTTPException(status_code=503, detail="Database unavailable")
        doc = await db.scans.find_one({"_id": ObjectId(scan_id), "user_id": user["_id"]})
        if not doc:
            raise HTTPException(status_code=404, detail="Scan not found")
        doc["id"] = str(doc["_id"])
        del doc["_id"]
        if "content_hash" in doc:
            del doc["content_hash"]
        if "user_id" in doc:
            del doc["user_id"]
        return ScanResult(**doc)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/history")
async def clear_history(user: dict = Depends(_require_user)):
    """Clear all scan history."""
    try:
        db = get_db()
        if db is None:
            return {"deleted": 0, "message": "Database unavailable"}
        result = await db.scans.delete_many({"user_id": user["_id"]})
        return {"deleted": result.deleted_count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=True)
