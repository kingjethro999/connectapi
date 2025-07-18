from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, File, UploadFile, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Dict, List, Optional
import os
import cloudinary
import cloudinary.uploader
from dotenv import load_dotenv
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timezone, timedelta
from uuid import uuid4
import asyncio
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import json
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from bson import ObjectId

# --- CONFIG ---
load_dotenv()
cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_SECRET')
)

app = FastAPI(title="WebSocket-Only Real-Time Chat API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = os.getenv('SECRET', 'supersecret')
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# --- MONGODB SETUP ---
MONGO_URI = os.getenv("MONGO_URI") or "mongodb+srv://kingjethrojerry:seun2009@cluster0.td3zsoy.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
db = client[os.getenv("MONGO_DB", "connectdb")]  # database name

# --- ADMIN USER CONSTANTS ---
ADMIN_EMAIL = "jethrojerrybj@gmail.com"
ADMIN_PASSWORD = "seun2009"
ADMIN_PROFILE_PIC = "https://res.cloudinary.com/dcrh78d8z/image/upload/v1749708860/ignite_zzafoh.png"

# --- STARTUP: ENSURE ADMIN USER EXISTS ---
@app.on_event("startup")
async def ensure_admin_user():
    """Ensure admin user exists in the database on startup"""
    try:
        # Check if admin user already exists
        admin_exists = db.users.find_one({"email": ADMIN_EMAIL})
        
        if not admin_exists:
            # Get next available user ID
            last_user = db.users.find_one(sort=[("id", -1)])
            next_id = (last_user["id"] + 1) if last_user else 1
            
            # Create admin user
            admin_user = {
                "id": next_id,
                "username": ADMIN_EMAIL.split('@')[0],
                "email": ADMIN_EMAIL,
                "password_hash": pwd_context.hash(ADMIN_PASSWORD),
                "role": "admin",
                "profile_pic": ADMIN_PROFILE_PIC,
                "add_up_requests": [],
                "added_ups": [],
                "google_id": None,
                "github_id": None,
                "facebook_id": None
            }
            
            db.users.insert_one(admin_user)
            print(f"✅ Admin user created successfully with ID: {next_id}")
        else:
            print(f"✅ Admin user already exists with ID: {admin_exists['id']}")
            
    except Exception as e:
        print(f"❌ Error creating admin user: {str(e)}")

# --- UTILS ---
def get_user_by_username_or_email(identifier: str):
    return db.users.find_one({"$or": [{"username": identifier}, {"email": identifier}]})

def get_user_by_id(user_id: int):
    return db.users.find_one({"id": user_id})

def get_chat_by_id(chat_id: int):
    return db.chats.find_one({"id": chat_id})

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def validate_ws_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            return None
        user = get_user_by_username_or_email(username)
        return user
    except:
        return None

def create_and_store_message(db, chat, sender_id, content, mentions, media_url=None, media_type=None):
    msg_id = str(uuid4())
    message = {
        'id': msg_id,
        'sender_id': sender_id,
        'content': content,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'deleted_for': [],
        'deleted_for_everyone': False,
        'mentions': mentions or []
    }
    if media_url:
        message['media_url'] = media_url
    if media_type:
        message['media_type'] = media_type
    chat['messages'].append(message)
    sender_user = get_user_by_id(sender_id)
    sender_username = sender_user['username'] if sender_user and 'username' in sender_user else str(sender_id)
    for uid in chat['members']:
        if uid != sender_id:
            chat['unread_counts'][str(uid)] = chat['unread_counts'].get(str(uid), 0) + 1
    db.chats.update_one({"_id": chat["_id"]}, {"$set": {"messages": chat['messages']}})
    return message

# --- REAL-TIME MANAGER ---
class RealTimeManager:
    def __init__(self):
        self.user_connections: Dict[int, set] = {}
        self.chat_connections: Dict[int, set] = {}
        self.online_users: set = set()
    async def connect_user(self, user_id: int, websocket: WebSocket):
        await websocket.accept()
        if user_id not in self.user_connections:
            self.user_connections[user_id] = set()
        self.user_connections[user_id].add(websocket)
        self.online_users.add(user_id)
        await self.broadcast_user_status(user_id, "online")
    async def connect_chat(self, chat_id: int, user_id: int, websocket: WebSocket):
        if chat_id not in self.chat_connections:
            self.chat_connections[chat_id] = set()
        self.chat_connections[chat_id].add(websocket)
        await self.broadcast_to_chat(chat_id, {
            "type": "user_joined",
            "user_id": user_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, exclude_ws=websocket)
    def disconnect_user(self, user_id: int, websocket: WebSocket):
        if user_id in self.user_connections:
            self.user_connections[user_id].discard(websocket)
            if not self.user_connections[user_id]:
                del self.user_connections[user_id]
                self.online_users.discard(user_id)
                asyncio.create_task(self.broadcast_user_status(user_id, "offline"))
    def disconnect_chat(self, chat_id: int, user_id: int, websocket: WebSocket):
        if chat_id in self.chat_connections:
            self.chat_connections[chat_id].discard(websocket)
            if not self.chat_connections[chat_id]:
                del self.chat_connections[chat_id]
            else:
                asyncio.create_task(self.broadcast_to_chat(chat_id, {
                    "type": "user_left",
                    "user_id": user_id,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }, exclude_ws=websocket))
    async def broadcast_to_user(self, user_id: int, message: dict):
        if user_id in self.user_connections:
            disconnected = set()
            for ws in self.user_connections[user_id]:
                try:
                    await ws.send_json(message)
                except:
                    disconnected.add(ws)
            for ws in disconnected:
                self.user_connections[user_id].discard(ws)
    async def broadcast_to_chat(self, chat_id: int, message: dict, exclude_ws=None):
        if chat_id in self.chat_connections:
            disconnected = set()
            for ws in self.chat_connections[chat_id]:
                if ws != exclude_ws:
                    try:
                        await ws.send_json(message)
                    except:
                        disconnected.add(ws)
            for ws in disconnected:
                self.chat_connections[chat_id].discard(ws)
    async def broadcast_user_status(self, user_id: int, status: str):
        message = {
            "type": "user_status",
            "user_id": user_id,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        for uid in list(self.user_connections.keys()):
            await self.broadcast_to_user(uid, message)
    async def broadcast_to_chat_members(self, chat_id: int, message: dict):
        chat = get_chat_by_id(chat_id)
        if chat:
            for member_id in chat['members']:
                await self.broadcast_to_user(member_id, message)

manager = RealTimeManager()

# --- MAIN WEBSOCKET ENDPOINT ---
@app.websocket('/ws/realtime')
async def websocket_realtime(websocket: WebSocket):
    token = websocket.query_params.get('token')
    if not token:
        await websocket.close(code=1008, reason="No token provided")
        return
    user = validate_ws_token(token)
    if not user:
        await websocket.close(code=1008, reason="Invalid token")
        return
    user_id = user['id']
    current_chat_id = None
    await manager.connect_user(user_id, websocket)
    try:
        while True:
            data = await websocket.receive_json()
            message_type = data.get("type")
            if message_type == "join_chat":
                chat_id = data.get("chat_id")
                if chat_id:
                    if current_chat_id:
                        manager.disconnect_chat(current_chat_id, user_id, websocket)
                    current_chat_id = chat_id
                    await manager.connect_chat(chat_id, user_id, websocket)
                    chat = get_chat_by_id(chat_id)
                    if chat and user_id in chat['members']:
                        await websocket.send_json({
                            "type": "chat_history",
                            "chat_id": chat_id,
                            "messages": chat['messages'][-50:],
                            "members": chat['members']
                        })
            elif message_type == "send_message":
                chat_id = data.get("chat_id")
                content = data.get("content", "")
                mentions = data.get("mentions", [])
                media_url = data.get("media_url")
                media_type = data.get("media_type")
                if not chat_id:
                    await websocket.send_json({"type": "error", "message": "No chat_id provided"})
                    continue
                if not content and not media_url:
                    await websocket.send_json({"type": "error", "message": "Message must have content or media"})
                    continue
                chat = get_chat_by_id(chat_id)
                if not chat or user_id not in chat['members']:
                    await websocket.send_json({"type": "error", "message": "Chat not found or access denied"})
                    continue
                message = create_and_store_message(db, chat, user_id, content, mentions, media_url, media_type)
                await manager.broadcast_to_chat_members(chat_id, {
                    "type": "new_message",
                    "chat_id": chat_id,
                    "message": message
                })
            elif message_type == "typing":
                chat_id = data.get("chat_id")
                is_typing = data.get("is_typing", False)
                if chat_id:
                    await manager.broadcast_to_chat(chat_id, {
                        "type": "typing",
                        "chat_id": chat_id,
                        "user_id": user_id,
                        "is_typing": is_typing
                    }, exclude_ws=websocket)
            elif message_type == "send_add_up_request":
                to_user_id = data.get("to_user_id")
                if to_user_id:
                    to_user = get_user_by_id(to_user_id)
                    if not to_user:
                        await websocket.send_json({"type": "error", "message": "User not found"})
                        continue
                    if user_id == to_user_id:
                        await websocket.send_json({"type": "error", "message": "Cannot add yourself"})
                        continue
                    if user_id in to_user.get('add_up_requests', []):
                        await websocket.send_json({"type": "error", "message": "Request already sent"})
                        continue
                    if user_id in to_user.get('added_ups', []):
                        await websocket.send_json({"type": "error", "message": "Already added up"})
                        continue
                    db.users.update_one({"_id": to_user["_id"]}, {"$push": {"add_up_requests": user_id}})
                    await manager.broadcast_to_user(to_user_id, {
                        "type": "add_up_request",
                        "from_user_id": user_id,
                        "from_username": user['username'],
                        "from_profile_pic": user.get('profile_pic', ''),
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    })
                    await websocket.send_json({
                        "type": "add_up_request_sent",
                        "to_user_id": to_user_id
                    })
            elif message_type == "accept_add_up_request":
                from_user_id = data.get("from_user_id")
                if from_user_id:
                    current_user_data = get_user_by_id(user_id)
                    if not current_user_data or from_user_id not in current_user_data.get('add_up_requests', []):
                        await websocket.send_json({"type": "error", "message": "No such request"})
                        continue
                    current_user_data['add_up_requests'].remove(from_user_id)
                    if from_user_id not in current_user_data['added_ups']:
                        current_user_data['added_ups'].append(from_user_id)
                    from_user = get_user_by_id(from_user_id)
                    if from_user and user_id not in from_user['added_ups']:
                        db.users.update_one({"_id": current_user_data["_id"]}, {"$push": {"added_ups": user_id}})
                        db.users.update_one({"_id": from_user["_id"]}, {"$push": {"added_ups": user_id}})
                        await manager.broadcast_to_user(from_user_id, {
                            "type": "add_up_accepted",
                            "by_user_id": user_id,
                            "by_username": user['username'],
                            "by_profile_pic": user.get('profile_pic', ''),
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        })
                    await manager.broadcast_to_user(from_user_id, {
                        "type": "add_up_request_accepted",
                        "from_user_id": from_user_id
                    })
            elif message_type == "create_story":
                text = data.get("text", "")
                media_url = data.get("media_url", "")
                if not text and not media_url:
                    await websocket.send_json({"type": "error", "message": "Story must have text or media"})
                    continue
                story_id = str(uuid4())
                story = {
                    'id': story_id,
                    'user_id': user_id,
                    'username': user['username'],
                    'text': text,
                    'media_url': media_url,
                    'created_at': datetime.now(timezone.utc).isoformat()
                }
                db.stories.insert_one(story)
                for uid in list(manager.user_connections.keys()):
                    if uid != user_id:
                        await manager.broadcast_to_user(uid, {
                            "type": "new_story",
                            "story": story
                        })
                await websocket.send_json({
                    "type": "story_created",
                    "story": story
                })
            elif message_type == "get_online_users":
                await websocket.send_json({
                    "type": "online_users",
                    "users": list(manager.online_users)
                })
            elif message_type == "mark_chat_read":
                chat_id = data.get("chat_id")
                if chat_id:
                    chat = get_chat_by_id(chat_id)
                    if chat and user_id in chat['members']:
                        db.chats.update_one({"_id": chat["_id"]}, {"$set": {"unread_counts": {str(user_id): 0}}})
                        await websocket.send_json({
                            "type": "chat_marked_read",
                            "chat_id": chat_id
                        })
            elif message_type == "create_group":
                group_name = data.get("group_name", "")
                description = data.get("description", "")
                group_dp = data.get("group_dp", "")
                members = data.get("members", [])
                if user_id not in members:
                    members.append(user_id)
                group_id = str(uuid4())
                group = {
                    'id': group_id,
                    'type': 'group',
                    'group_name': group_name,
                    'description': description,
                    'group_dp': group_dp,
                    'members': members,
                    'admins': [user_id],
                    'messages': [],
                    'pinned': [],
                    'archived': [],
                    'edit_permissions': 'admin',
                    'unread_counts': {str(uid): 0 for uid in members},
                    'blocked_users': []
                }
                db.chats.insert_one(group)
                for uid in members:
                    await manager.broadcast_to_user(uid, {
                        "type": "group_created",
                        "group": group
                    })
                await websocket.send_json({"type": "group_created", "group": group})
            elif message_type == "add_group_member":
                group_id = data.get("group_id")
                user_to_add = data.get("user_id")
                group = get_chat_by_id(group_id)
                if not group or user_id not in group.get('admins', []):
                    await websocket.send_json({"type": "error", "message": "Not allowed"})
                    continue
                if user_to_add not in group['members']:
                    group['members'].append(user_to_add)
                    group['unread_counts'][str(user_to_add)] = 0
                    db.chats.update_one({"_id": group["_id"]}, {"$push": {"members": user_to_add}})
                    db.chats.update_one({"_id": group["_id"]}, {"$set": {"unread_counts": group['unread_counts']}})
                    await manager.broadcast_to_user(user_to_add, {"type": "added_to_group", "group": group})
                await manager.broadcast_to_chat_members(group_id, {"type": "group_updated", "group": group})
            elif message_type == "remove_group_member":
                group_id = data.get("group_id")
                user_to_remove = data.get("user_id")
                group = get_chat_by_id(group_id)
                if not group or user_id not in group.get('admins', []):
                    await websocket.send_json({"type": "error", "message": "Not allowed"})
                    continue
                if user_to_remove in group['members']:
                    group['members'].remove(user_to_remove)
                    group['unread_counts'].pop(str(user_to_remove), None)
                    if user_to_remove in group.get('admins', []):
                        group['admins'].remove(user_to_remove)
                    db.chats.update_one({"_id": group["_id"]}, {"$pull": {"members": user_to_remove}})
                    db.chats.update_one({"_id": group["_id"]}, {"$set": {"unread_counts": group['unread_counts']}})
                    await manager.broadcast_to_user(user_to_remove, {"type": "removed_from_group", "group_id": group_id})
                await manager.broadcast_to_chat_members(group_id, {"type": "group_updated", "group": group})
            elif message_type == "edit_group":
                group_id = data.get("group_id")
                group_name = data.get("group_name")
                description = data.get("description")
                group_dp = data.get("group_dp")
                edit_permissions = data.get("edit_permissions")
                group = get_chat_by_id(group_id)
                if not group or user_id not in group.get('admins', []):
                    await websocket.send_json({"type": "error", "message": "Not allowed"})
                    continue
                if group_name is not None:
                    group['group_name'] = group_name
                if description is not None:
                    group['description'] = description
                if group_dp is not None:
                    group['group_dp'] = group_dp
                if edit_permissions is not None:
                    group['edit_permissions'] = edit_permissions
                db.chats.update_one({"_id": group["_id"]}, {"$set": group})
                await manager.broadcast_to_chat_members(group_id, {"type": "group_updated", "group": group})
            elif message_type == "delete_group":
                group_id = data.get("group_id")
                group = get_chat_by_id(group_id)
                if not group or user_id not in group.get('admins', []):
                    await websocket.send_json({"type": "error", "message": "Not allowed"})
                    continue
                db.chats.delete_one({"_id": group["_id"]})
                await manager.broadcast_to_chat_members(group_id, {"type": "group_deleted", "group_id": group_id})
    except WebSocketDisconnect:
        manager.disconnect_user(user_id, websocket)
        if current_chat_id:
            manager.disconnect_chat(current_chat_id, user_id, websocket)

# --- REST ENDPOINTS: Auth, Uploads, Profile, Initial Fetch ---
class RegisterModel(BaseModel):
    username: str
    email: str
    password: str
    profile_pic: Optional[str] = None
class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    user: dict
class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    profile_pic: str
@app.post('/auth/register', response_model=LoginResponse)
def register(data: RegisterModel):
    if db.users.find_one({"username": data.username}):
        raise HTTPException(status_code=400, detail='Username already registered')
    if db.users.find_one({"email": data.email}):
        raise HTTPException(status_code=400, detail='Email already registered')
    
    # Get next available user ID
    last_user = db.users.find_one(sort=[("id", -1)])
    user_id = (last_user["id"] + 1) if last_user else 1
    
    user = {
        'id': user_id,
        'username': data.username,
        'email': data.email,
        'password_hash': get_password_hash(data.password),
        'role': 'user',
        'profile_pic': data.profile_pic or "",
        'add_up_requests': [],
        'added_ups': [],
        'google_id': None,
        'github_id': None,
        'facebook_id': None
    }
    db.users.insert_one(user)
    access_token = create_access_token(data={"sub": user['username']})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user['id'],
            "username": user['username'],
            "role": user['role'],
            "profile_pic": user.get('profile_pic', '')
        }
    }
@app.post('/auth/login', response_model=LoginResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_username_or_email(form_data.username)
    if not user or not verify_password(form_data.password, user.get('password_hash', '')):
        raise HTTPException(status_code=400, detail="Incorrect username/email or password")
    access_token = create_access_token(data={"sub": user['username']})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user['id'],
            "username": user['username'],
            "role": user['role'],
            "profile_pic": user.get('profile_pic', '')
        }
    }
@app.get('/profile/me', response_model=UserResponse)
def get_my_profile(token: str = Depends(oauth2_scheme)):
    user = validate_ws_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {
        "id": user['id'],
        "username": user['username'],
        "role": user['role'],
        "profile_pic": user.get('profile_pic', '')
    }
@app.post('/upload/profile-pic')
def upload_profile_pic(file: UploadFile = File(...), token: str = Depends(oauth2_scheme)):
    user = validate_ws_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    try:
        result = cloudinary.uploader.upload(file.file, folder="profile_pics")
        url = result.get('secure_url')
        db.users.update_one({"_id": user["_id"]}, {"$set": {"profile_pic": url}})
        return {"profile_pic_url": url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")
@app.post('/upload/chat-media')
def upload_chat_media(file: UploadFile = File(...), token: str = Depends(oauth2_scheme)):
    user = validate_ws_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    try:
        resource_type = 'video' if file.content_type and file.content_type.startswith('video') else 'image'
        result = cloudinary.uploader.upload(file.file, folder="chat_media", resource_type=resource_type)
        url = result.get('secure_url')
        return {"media_url": url, "media_type": resource_type}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")
@app.post('/upload/story-media')
def upload_story_media(file: UploadFile = File(...), token: str = Depends(oauth2_scheme)):
    user = validate_ws_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    try:
        resource_type = 'video' if file.content_type and file.content_type.startswith('video') else 'image'
        result = cloudinary.uploader.upload(file.file, folder="stories", resource_type=resource_type)
        url = result.get('secure_url')
        return {"media_url": url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")
@app.get('/chats')
def get_chats(token: str = Depends(oauth2_scheme)):
    user = validate_ws_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return fix_ids(list(db.chats.find({"type": "group"})) + list(db.chats.find({"type": "direct"})))
@app.get('/users')
def get_users(search: str = "", token: str = Depends(oauth2_scheme)):
    user = validate_ws_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    if search:
        # Case-insensitive search on username or email
        return fix_ids(list(db.users.find({
            "$or": [
                {"username": {"$regex": search, "$options": "i"}},
                {"email": {"$regex": search, "$options": "i"}}
            ]
        })))
    return fix_ids(list(db.users.find({})))
@app.get('/stories')
def get_stories(token: str = Depends(oauth2_scheme)):
    user = validate_ws_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return fix_ids(list(db.stories.find({})))

@app.get('/search/users')
def search_users(search: str = "", token: str = Depends(oauth2_scheme)):
    # Proxy to /users?search= for frontend compatibility
    return get_users(search, token)

async def cleanup_expired_stories():
    while True:
        now = datetime.now(timezone.utc)
        db.stories.delete_many({"created_at": {"$lt": now - timedelta(days=1)}})
        await asyncio.sleep(60)  # Run every 10 minutes

@app.on_event("startup")
async def start_story_cleanup_task():
    asyncio.create_task(cleanup_expired_stories())

def fix_ids(doc):
    if isinstance(doc, list):
        return [fix_ids(d) for d in doc]
    if isinstance(doc, dict):
        return {k: (str(v) if isinstance(v, ObjectId) else fix_ids(v)) for k, v in doc.items()}
    return doc

@app.get('/admin/db')
def get_all_collections(request: Request):
    return {
        "users": fix_ids(list(db.users.find({}))),
        "chats": fix_ids(list(db.chats.find({}))),
        "stories": fix_ids(list(db.stories.find({}))),
        "settings": fix_ids(list(db.settings.find({}))) if db.settings.find_one({}) else []
    }

@app.get('/')
def root():
    return {"status": "ok", "message": "Connect backend is running"}

@app.get("/index.html")
def read_index():
    return FileResponse("index.html")

# --- END ---