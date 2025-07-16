from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional
import json
import os
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
import random
from fastapi import Body
import cloudinary
import cloudinary.uploader
from fastapi import File, UploadFile, Form
from dotenv import load_dotenv
from datetime import timezone
import requests
from pydantic import BaseModel
from fastapi import Query
from fastapi import WebSocket, WebSocketDisconnect
from typing import Set
import smtplib
from email.message import EmailMessage
from fastapi import BackgroundTasks

# Load .env if present
load_dotenv()

cloudinary.config(
    cloud_name=os.getenv('CLOUDINARY_CLOUD_NAME'),
    api_key=os.getenv('CLOUDINARY_API_KEY'),
    api_secret=os.getenv('CLOUDINARY_SECRET')
)

app = FastAPI(
    title="React Native Chat API",
    description="Backend API for React Native Chat App",
    version="1.0.0"
)

# Add CORS middleware (useful for testing and web debugging)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For React Native, this is not strictly needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_FILE = 'data.json'

def read_data() -> dict:
    if not os.path.exists(DATA_FILE):
        return {"users": [], "chats": [], "stories": [], "settings": {}}
    with open(DATA_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def write_data(data: dict):
    with open(DATA_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)

# --- Auth Config ---
SECRET_KEY = os.getenv('SECRET', 'supersecret')
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days for mobile apps

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user_by_username_or_email(identifier: str):
    data = read_data()
    for user in data.get('users', []):
        if user.get('username') == identifier or user.get('email') == identifier:
            return user
    return None

def authenticate_user(identifier: str, password: str):
    user = get_user_by_username_or_email(identifier)
    if not user or not verify_password(password, user.get('password_hash', '')):
        return None
    return user

def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_username_or_email(username)
    if user is None:
        raise credentials_exception
    return user

# --- Pydantic Models for React Native ---
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

class StoryResponse(BaseModel):
    id: int
    user_id: int
    username: str
    text: str
    media_url: str
    created_at: str

class MessageResponse(BaseModel):
    msg: str

class ResetPasswordModel(BaseModel):
    username: str
    new_password: str

# --- Admin Setup ---
ADMIN_EMAIL = "jethrojerrybj@gmail.com"
ADMIN_PASSWORD = "seun2009"
ADMIN_PROFILE_PIC = "https://res.cloudinary.com/dcrh78d8z/image/upload/v1749708860/ignite_zzafoh.png"

def ensure_admin():
    db = read_data()
    if not any(u.get("username") == ADMIN_EMAIL for u in db["users"]):
        user_id = max([u.get('id', 0) for u in db['users']] + [0]) + 1
        admin_user = {
            "id": user_id,
            "username": ADMIN_EMAIL,
            "password_hash": get_password_hash(ADMIN_PASSWORD),
            "role": "admin",
            "profile_pic": ADMIN_PROFILE_PIC
        }
        db["users"].append(admin_user)
        write_data(db)

ensure_admin()

# --- Auth Endpoints ---
@app.post('/auth/register', response_model=MessageResponse)
def register(data: RegisterModel):
    db = read_data()
    # Check for existing username or email
    for user in db['users']:
        if user['username'] == data.username:
            raise HTTPException(status_code=400, detail='Username already registered')
        if user['email'] == data.email:
            raise HTTPException(status_code=400, detail='Email already registered')
    user_id = max([u.get('id', 0) for u in db['users']] + [0]) + 1
    user = {
        'id': user_id,
        'username': data.username,
        'email': data.email,
        'password_hash': get_password_hash(data.password),
        'role': 'admin' if data.username == ADMIN_EMAIL else 'user',
        'profile_pic': data.profile_pic or "",
        'google_id': None,
        'github_id': None,
        'facebook_id': None
    }
    db['users'].append(user)
    write_data(db)
    return {"msg": "User registered successfully"}

@app.post('/auth/login', response_model=LoginResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username/email or password")
    access_token = create_access_token(data={"sub": user['username']})
    user_data = {
        "id": user['id'],
        "username": user['username'],
        "role": user['role'],
        "profile_pic": user.get('profile_pic', '')
    }
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_data
    }

@app.post('/auth/reset-password', response_model=MessageResponse)
def reset_password(data: ResetPasswordModel):
    db = read_data()
    for user in db['users']:
        if user['username'] == data.username:
            user['password_hash'] = get_password_hash(data.new_password)
            write_data(db)
            return {"msg": "Password reset successful"}
    raise HTTPException(status_code=404, detail="User not found")

# --- User Profile Endpoints ---
@app.get('/profile/me', response_model=UserResponse)
def get_my_profile(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user['id'],
        "username": current_user['username'],
        "role": current_user['role'],
        "profile_pic": current_user.get('profile_pic', '')
    }

@app.put('/profile/me', response_model=UserResponse)
def update_my_profile(profile_pic: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    db = read_data()
    for user in db['users']:
        if user['id'] == current_user['id']:
            if profile_pic is not None:
                user['profile_pic'] = profile_pic
            write_data(db)
            return {
                "id": user['id'],
                "username": user['username'],
                "role": user['role'],
                "profile_pic": user.get('profile_pic', '')
            }
    raise HTTPException(status_code=404, detail="User not found")

# --- Admin Endpoints ---
def require_admin(current_user: dict = Depends(get_current_user)):
    if current_user.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

@app.get('/admin/users', response_model=List[UserResponse])
def admin_get_users(current_user: dict = Depends(require_admin)):
    data = read_data()
    return [
        {
            "id": user['id'],
            "username": user['username'],
            "role": user['role'],
            "profile_pic": user.get('profile_pic', '')
        }
        for user in data.get('users', [])
    ]

# --- File Upload Endpoints ---
@app.post('/upload/profile-pic')
def upload_profile_pic(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    try:
        result = cloudinary.uploader.upload(file.file, folder="profile_pics")
        url = result.get('secure_url')
        
        # Update user profile_pic
        db = read_data()
        for user in db['users']:
            if user['username'] == current_user['username']:
                user['profile_pic'] = url
                break
        write_data(db)
        
        return {"profile_pic_url": url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.post('/upload/story-media')
def upload_story_media(file: UploadFile = File(...), current_user: dict = Depends(get_current_user)):
    try:
        resource_type = 'video' if file.content_type and file.content_type.startswith('video') else 'image'
        result = cloudinary.uploader.upload(file.file, folder="stories", resource_type=resource_type)
        url = result.get('secure_url')
        return {"media_url": url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

# --- Story Endpoints ---
@app.post('/stories', response_model=StoryResponse)
def create_story(background_tasks: BackgroundTasks, text: str = Form(...), media_url: str = Form(""), current_user: dict = Depends(get_current_user)):
    db = read_data()
    story_id = max([s.get('id', 0) for s in db['stories']] + [0]) + 1
    story = {
        'id': story_id,
        'user_id': current_user['id'],
        'username': current_user['username'],
        'text': text,
        'media_url': media_url,
        'created_at': datetime.now(timezone.utc).isoformat()
    }
    db['stories'].append(story)
    write_data(db)
    # Notify all users except the creator
    for user in db['users']:
        if user['id'] != current_user['id'] and user.get('email'):
            background_tasks.add_task(
                send_notification_email,
                user['email'],
                'New Story Posted',
                f"{current_user['username']} posted a new story on CONNECT NOW."
            )
    return story

@app.get('/stories', response_model=List[StoryResponse])
def get_stories(current_user: dict = Depends(get_current_user)):
    db = read_data()
    now = datetime.now(timezone.utc)
    
    # Only return stories from last 24 hours
    fresh_stories = []
    changed = False
    for s in db['stories']:
        try:
            created = datetime.fromisoformat(s['created_at'])
            if (now - created).total_seconds() <= 86400:  # 24 hours
                fresh_stories.append(s)
            else:
                changed = True
        except ValueError:
            # Handle invalid datetime format
            changed = True
            continue
    
    if changed:
        db['stories'] = fresh_stories
        write_data(db)
    
    return fresh_stories

# --- Chat Endpoints ---
@app.get('/chats')
def get_chats(current_user: dict = Depends(get_current_user)):
    data = read_data()
    return data.get('chats', [])

@app.post('/chats')
def create_chat(chat: Dict[str, Any], current_user: dict = Depends(get_current_user)):
    data = read_data()
    chat_id = max([c.get('id', 0) for c in data.get('chats', [])] + [0]) + 1
    chat['id'] = chat_id
    chat['created_at'] = datetime.now(timezone.utc).isoformat()
    data['chats'].append(chat)
    write_data(data)
    return chat

@app.get('/chats/{chat_id}')
def get_chat(chat_id: int, current_user: dict = Depends(get_current_user)):
    data = read_data()
    for chat in data.get('chats', []):
        if chat.get('id') == chat_id:
            return chat
    raise HTTPException(status_code=404, detail='Chat not found')

@app.put('/chats/{chat_id}')
def update_chat(chat_id: int, chat: Dict[str, Any], current_user: dict = Depends(get_current_user)):
    data = read_data()
    chats = data.get('chats', [])
    for idx, c in enumerate(chats):
        if c.get('id') == chat_id:
            chat['id'] = chat_id
            chat['updated_at'] = datetime.now(timezone.utc).isoformat()
            chats[idx] = chat
            write_data(data)
            return chat
    raise HTTPException(status_code=404, detail='Chat not found')

@app.delete('/chats/{chat_id}')
def delete_chat(chat_id: int, current_user: dict = Depends(get_current_user)):
    data = read_data()
    chats = data.get('chats', [])
    data['chats'] = [c for c in chats if c.get('id') != chat_id]
    write_data(data)
    return {"detail": "Chat deleted"}

# --- Search Endpoints ---
@app.get('/search/users')
def search_users(q: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    data = read_data()
    users = data.get('users', [])
    
    if q:
        filtered_users = [u for u in users if q.lower() in u.get('username', '').lower()]
    else:
        filtered_users = random.sample(users, min(5, len(users)))
    
    # Return user data without sensitive information
    return [
        {
            "id": user['id'],
            "username": user['username'],
            "profile_pic": user.get('profile_pic', '')
        }
        for user in filtered_users
    ]

# --- Settings Endpoints ---
@app.get('/settings')
def get_my_settings(current_user: dict = Depends(get_current_user)):
    data = read_data()
    settings = data.get('settings', {})
    return settings.get(str(current_user['id']), {})

@app.put('/settings')
def update_my_settings(settings: Dict[str, Any], current_user: dict = Depends(get_current_user)):
    data = read_data()
    if 'settings' not in data:
        data['settings'] = {}
    data['settings'][str(current_user['id'])] = settings
    write_data(data)
    return settings

# --- Social Auth Endpoints ---
def get_or_create_social_user(provider, social_id, email, name, profile_pic):
    db = read_data()
    # Try to find user by provider id
    for user in db['users']:
        if user.get(f'{provider}_id') == social_id:
            return user
    
    # If not found, create new user
    user_id = max([u.get('id', 0) for u in db['users']] + [0]) + 1
    user = {
        'id': user_id,
        'username': name or email or f'{provider}_{social_id}',
        'email': email or '',
        f'{provider}_id': social_id,
        'role': 'user',
        'profile_pic': profile_pic or ''
    }
    db['users'].append(user)
    write_data(db)
    return user

@app.post('/auth/google', response_model=LoginResponse)
def google_auth(token: str = Body(...)):
    try:
        resp = requests.get(f'https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={token}')
        if resp.status_code != 200:
            raise HTTPException(status_code=400, detail='Invalid Google token')
        
        info = resp.json()
        user = get_or_create_social_user(
            'google',
            info['sub'],
            info.get('email'),
            info.get('name'),
            info.get('picture')
        )
        
        access_token = create_access_token(data={"sub": user['username']})
        
        user_data = {
            "id": user['id'],
            "username": user['username'],
            "role": user['role'],
            "profile_pic": user.get('profile_pic', '')
        }
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user_data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Google auth failed: {str(e)}")

@app.post('/auth/github', response_model=LoginResponse)
def github_auth(token: str = Body(...)):
    try:
        headers = {'Authorization': f'token {token}'}
        resp = requests.get('https://api.github.com/user', headers=headers)
        if resp.status_code != 200:
            raise HTTPException(status_code=400, detail='Invalid GitHub token')
        
        info = resp.json()
        email = info.get('email')
        
        # If email is not public, fetch from emails endpoint
        if not email:
            emails_resp = requests.get('https://api.github.com/user/emails', headers=headers)
            if emails_resp.status_code == 200:
                emails = emails_resp.json()
                email = next((e['email'] for e in emails if e.get('primary')), None)
        
        user = get_or_create_social_user(
            'github',
            str(info['id']),
            email,
            info.get('login'),
            info.get('avatar_url')
        )
        
        access_token = create_access_token(data={"sub": user['username']})
        
        user_data = {
            "id": user['id'],
            "username": user['username'],
            "role": user['role'],
            "profile_pic": user.get('profile_pic', '')
        }
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": user_data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"GitHub auth failed: {str(e)}")

# --- Add Up (Friend Request) Endpoints ---
# Helper to get user by id
def get_user_by_id(user_id: int):
    data = read_data()
    for user in data.get('users', []):
        if user.get('id') == user_id:
            return user
    return None

# Ensure all users have add_up_requests and added_ups fields
def ensure_add_up_fields():
    db = read_data()
    changed = False
    for user in db['users']:
        if 'add_up_requests' not in user:
            user['add_up_requests'] = []
            changed = True
        if 'added_ups' not in user:
            user['added_ups'] = []
            changed = True
    if changed:
        write_data(db)

ensure_add_up_fields()

# --- Email Notification Helper ---
SMTP_USER = os.getenv('GMAIL_SMTP_USER')
SMTP_PASS = os.getenv('GMAIL_APP_PASSWORD')
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SENDER_NAME = 'CONNECT NOW'

# Send email in background
def send_notification_email(to_email: str, subject: str, body: str):
    if not SMTP_USER or not SMTP_PASS:
        return
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = f'{SENDER_NAME} <{SMTP_USER}>'
    msg['To'] = to_email
    msg.set_content(body)
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
    except Exception as e:
        print(f"Email send failed: {e}")

# --- Example: Add Up Request Notification ---
@app.post('/add-up/request', response_model=MessageResponse)
def send_add_up_request(background_tasks: BackgroundTasks, to_user_id: int = Body(...), current_user: dict = Depends(get_current_user)):
    db = read_data()
    to_user = get_user_by_id(to_user_id)
    if not to_user:
        raise HTTPException(status_code=404, detail="User not found")
    if current_user['id'] == to_user_id:
        raise HTTPException(status_code=400, detail="Cannot add yourself")
    if current_user['id'] in to_user.get('add_up_requests', []):
        raise HTTPException(status_code=400, detail="Request already sent")
    if current_user['id'] in to_user.get('added_ups', []):
        raise HTTPException(status_code=400, detail="Already added up")
    to_user['add_up_requests'].append(current_user['id'])
    write_data(db)
    # Send notification email
    if to_user.get('email'):
        background_tasks.add_task(
            send_notification_email,
            to_user['email'],
            'New Add Up Request',
            f"You have a new add up request from {current_user['username']} on CONNECT NOW."
        )
    return {"msg": "Add up request sent"}

@app.get('/add-up/requests')
def get_add_up_requests(current_user: dict = Depends(get_current_user)):
    db = read_data()
    requesters = [get_user_by_id(uid) for uid in current_user.get('add_up_requests', [])]
    return [
        {"id": u['id'], "username": u['username'], "profile_pic": u.get('profile_pic', '')}
        for u in requesters if u
    ]

@app.post('/add-up/accept', response_model=MessageResponse)
def accept_add_up_request(from_user_id: int = Body(...), current_user: dict = Depends(get_current_user)):
    db = read_data()
    if from_user_id not in current_user.get('add_up_requests', []):
        raise HTTPException(status_code=400, detail="No such request")
    # Remove from requests
    current_user['add_up_requests'].remove(from_user_id)
    # Add to added_ups for both users
    if from_user_id not in current_user['added_ups']:
        current_user['added_ups'].append(from_user_id)
    from_user = get_user_by_id(from_user_id)
    if from_user and current_user['id'] not in from_user['added_ups']:
        from_user['added_ups'].append(current_user['id'])
    write_data(db)
    return {"msg": "Add up request accepted"}

@app.post('/add-up/reject', response_model=MessageResponse)
def reject_add_up_request(from_user_id: int = Body(...), current_user: dict = Depends(get_current_user)):
    db = read_data()
    if from_user_id not in current_user.get('add_up_requests', []):
        raise HTTPException(status_code=400, detail="No such request")
    current_user['add_up_requests'].remove(from_user_id)
    write_data(db)
    return {"msg": "Add up request rejected"}

# --- P2P Chat System ---
from uuid import uuid4

# Helper to get chat by id
def get_chat_by_id(chat_id: int):
    data = read_data()
    for chat in data.get('chats', []):
        if chat.get('id') == chat_id:
            return chat
    return None

# Helper to get or create a P2P chat between two users
def get_or_create_p2p_chat(user1_id: int, user2_id: int):
    db = read_data()
    for chat in db['chats']:
        if chat.get('type') == 'p2p' and set(chat['members']) == set([user1_id, user2_id]):
            return chat
    # Create new chat
    chat_id = max([c.get('id', 0) for c in db['chats']] + [0]) + 1
    chat = {
        'id': chat_id,
        'type': 'p2p',
        'members': [user1_id, user2_id],
        'messages': [],
        'blocked_users': [],
        'pinned': [],
        'archived': [],
        'unread_counts': {str(user1_id): 0, str(user2_id): 0}
    }
    db['chats'].append(chat)
    write_data(db)
    return chat

@app.post('/chats/p2p')
def start_or_get_p2p_chat(other_user_id: int = Body(...), current_user: dict = Depends(get_current_user)):
    chat = get_or_create_p2p_chat(current_user['id'], other_user_id)
    return chat

@app.post('/chats/{chat_id}/messages')
def send_message(background_tasks: BackgroundTasks, chat_id: int, content: str = Body(...), current_user: dict = Depends(get_current_user)):
    db = read_data()
    chat = get_chat_by_id(chat_id)
    if not chat or current_user['id'] not in chat['members']:
        raise HTTPException(status_code=404, detail="Chat not found or access denied")
    msg_id = str(uuid4())
    message = {
        'id': msg_id,
        'sender_id': current_user['id'],
        'content': content,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'deleted_for': [],
        'deleted_for_everyone': False
    }
    chat['messages'].append(message)
    # Update unread counts for other members
    for uid in chat['members']:
        if uid != current_user['id']:
            chat['unread_counts'][str(uid)] = chat['unread_counts'].get(str(uid), 0) + 1
            # Send notification email to other members
            other_user = get_user_by_id(uid)
            if other_user and other_user.get('email'):
                background_tasks.add_task(
                    send_notification_email,
                    other_user['email'],
                    'New Chat Message',
                    f"You have a new message from {current_user['username']} in CONNECT NOW."
                )
    # Notify mentioned users (if any)
    mentions = []
    if hasattr(message, 'mentions'):
        mentions = message['mentions']
    for uid in mentions:
        if uid != current_user['id']:
            user = get_user_by_id(uid)
            if user and user.get('email'):
                background_tasks.add_task(
                    send_notification_email,
                    user['email'],
                    'You were mentioned in a message',
                    f"You were mentioned by {current_user['username']} in a chat on CONNECT NOW."
                )
    write_data(db)
    return message

@app.post('/chats/{chat_id}/block')
def block_user_in_chat(chat_id: int, current_user: dict = Depends(get_current_user)):
    db = read_data()
    chat = get_chat_by_id(chat_id)
    if not chat or current_user['id'] not in chat['members']:
        raise HTTPException(status_code=404, detail="Chat not found or access denied")
    if current_user['id'] not in chat['blocked_users']:
        chat['blocked_users'].append(current_user['id'])
        write_data(db)
    return {"msg": "User blocked in chat"}

@app.post('/chats/{chat_id}/unblock')
def unblock_user_in_chat(chat_id: int, current_user: dict = Depends(get_current_user)):
    db = read_data()
    chat = get_chat_by_id(chat_id)
    if not chat or current_user['id'] not in chat['members']:
        raise HTTPException(status_code=404, detail="Chat not found or access denied")
    if current_user['id'] in chat['blocked_users']:
        chat['blocked_users'].remove(current_user['id'])
        write_data(db)
    return {"msg": "User unblocked in chat"}

@app.post('/chats/{chat_id}/pin')
def pin_chat(chat_id: int, current_user: dict = Depends(get_current_user)):
    db = read_data()
    chat = get_chat_by_id(chat_id)
    if not chat or current_user['id'] not in chat['members']:
        raise HTTPException(status_code=404, detail="Chat not found or access denied")
    # Count total pins for user (chats + groups)
    total_pins = 0
    for c in db['chats']:
        if current_user['id'] in c.get('pinned', []):
            total_pins += 1
    if total_pins >= 5:
        raise HTTPException(status_code=400, detail="Max 5 pins allowed")
    if current_user['id'] not in chat['pinned']:
        chat['pinned'].append(current_user['id'])
        write_data(db)
    return {"msg": "Chat pinned"}

@app.post('/chats/{chat_id}/archive')
def archive_chat(chat_id: int, current_user: dict = Depends(get_current_user)):
    db = read_data()
    chat = get_chat_by_id(chat_id)
    if not chat or current_user['id'] not in chat['members']:
        raise HTTPException(status_code=404, detail="Chat not found or access denied")
    if current_user['id'] not in chat['archived']:
        chat['archived'].append(current_user['id'])
        write_data(db)
    return {"msg": "Chat archived"}

@app.delete('/chats/{chat_id}/messages/{message_id}')
def delete_message(chat_id: int, message_id: str, for_everyone: bool = False, current_user: dict = Depends(get_current_user)):
    db = read_data()
    chat = get_chat_by_id(chat_id)
    if not chat or current_user['id'] not in chat['members']:
        raise HTTPException(status_code=404, detail="Chat not found or access denied")
    for msg in chat['messages']:
        if msg['id'] == message_id:
            if for_everyone:
                if msg['sender_id'] != current_user['id']:
                    raise HTTPException(status_code=403, detail="Only sender can delete for everyone")
                msg['deleted_for_everyone'] = True
            else:
                if current_user['id'] not in msg['deleted_for']:
                    msg['deleted_for'].append(current_user['id'])
            write_data(db)
            return {"msg": "Message deleted"}
    raise HTTPException(status_code=404, detail="Message not found")

@app.get('/chats/unread-count')
def get_unread_counts(current_user: dict = Depends(get_current_user)):
    db = read_data()
    result = []
    for chat in db['chats']:
        if chat.get('type') == 'p2p' and current_user['id'] in chat['members']:
            count = chat['unread_counts'].get(str(current_user['id']), 0)
            result.append({"chat_id": chat['id'], "unread_count": count})
    return result

# --- Group Chat System ---

def get_group_by_id(group_id: int):
    data = read_data()
    for chat in data.get('chats', []):
        if chat.get('type') == 'group' and chat.get('id') == group_id:
            return chat
    return None

@app.post('/groups')
def create_group(
    background_tasks: BackgroundTasks,
    group_name: str = Body(...),
    description: str = Body(""),
    group_dp: str = Body(""),
    members: list = Body(...),
    current_user: dict = Depends(get_current_user)
):
    db = read_data()
    group_id = max([c.get('id', 0) for c in db['chats']] + [0]) + 1
    # Ensure creator is in members and admin
    if current_user['id'] not in members:
        members.append(current_user['id'])
    group = {
        'id': group_id,
        'type': 'group',
        'group_name': group_name,
        'description': description,
        'group_dp': group_dp,
        'members': members,
        'admins': [current_user['id']],
        'messages': [],
        'pinned': [],
        'archived': [],
        'edit_permissions': 'admin',  # or 'all'
        'unread_counts': {str(uid): 0 for uid in members}
    }
    db['chats'].append(group)
    write_data(db)
    # Notify all members except creator
    for uid in members:
        if uid != current_user['id']:
            user = get_user_by_id(uid)
            if user and user.get('email'):
                background_tasks.add_task(
                    send_notification_email,
                    user['email'],
                    'Added to New Group',
                    f"You have been added to group '{group_name}' on CONNECT NOW."
                )
    return group

@app.put('/groups/{group_id}')
def edit_group(
    background_tasks: BackgroundTasks,
    group_id: int,
    group_name: Optional[str] = Body(None),
    description: Optional[str] = Body(None),
    group_dp: Optional[str] = Body(None),
    edit_permissions: Optional[str] = Body(None),
    current_user: dict = Depends(get_current_user)
):
    db = read_data()
    group = get_group_by_id(group_id)
    if not group or current_user['id'] not in group['admins']:
        raise HTTPException(status_code=403, detail="Only admins can edit group info")
    if group_name is not None:
        group['group_name'] = group_name
    if description is not None:
        group['description'] = description
    if group_dp is not None:
        group['group_dp'] = group_dp
    if edit_permissions is not None:
        group['edit_permissions'] = edit_permissions
    write_data(db)
    # Notify all members except editor
    for uid in group['members']:
        if uid != current_user['id']:
            user = get_user_by_id(uid)
            if user and user.get('email'):
                background_tasks.add_task(
                    send_notification_email,
                    user['email'],
                    'Group Info Updated',
                    f"Group '{group['group_name']}' was updated by {current_user['username']} on CONNECT NOW."
                )
    return group

@app.post('/groups/{group_id}/add-member')
def add_member_to_group(group_id: int, user_id: int = Body(...), current_user: dict = Depends(get_current_user)):
    db = read_data()
    group = get_group_by_id(group_id)
    if not group or (group['edit_permissions'] == 'admin' and current_user['id'] not in group['admins']):
        raise HTTPException(status_code=403, detail="Not allowed to add members")
    if user_id not in group['members']:
        group['members'].append(user_id)
        group['unread_counts'][str(user_id)] = 0
        write_data(db)
    return {"msg": "Member added"}

@app.post('/groups/{group_id}/remove-member')
def remove_member_from_group(group_id: int, user_id: int = Body(...), current_user: dict = Depends(get_current_user)):
    db = read_data()
    group = get_group_by_id(group_id)
    if not group or (group['edit_permissions'] == 'admin' and current_user['id'] not in group['admins']):
        raise HTTPException(status_code=403, detail="Not allowed to remove members")
    if user_id in group['members']:
        group['members'].remove(user_id)
        group['unread_counts'].pop(str(user_id), None)
        if user_id in group['admins']:
            group['admins'].remove(user_id)
        write_data(db)
    return {"msg": "Member removed"}

@app.post('/groups/{group_id}/add-admin')
def add_admin_to_group(group_id: int, user_id: int = Body(...), current_user: dict = Depends(get_current_user)):
    db = read_data()
    group = get_group_by_id(group_id)
    if not group or current_user['id'] not in group['admins']:
        raise HTTPException(status_code=403, detail="Only admins can add admins")
    if user_id in group['members'] and user_id not in group['admins']:
        group['admins'].append(user_id)
        write_data(db)
    return {"msg": "Admin added"}

@app.post('/groups/{group_id}/remove-admin')
def remove_admin_from_group(group_id: int, user_id: int = Body(...), current_user: dict = Depends(get_current_user)):
    db = read_data()
    group = get_group_by_id(group_id)
    if not group or current_user['id'] not in group['admins']:
        raise HTTPException(status_code=403, detail="Only admins can remove admins")
    if user_id in group['admins'] and user_id != current_user['id']:
        group['admins'].remove(user_id)
        write_data(db)
    return {"msg": "Admin removed"}

@app.post('/groups/{group_id}/pin')
def pin_group(group_id: int, current_user: dict = Depends(get_current_user)):
    db = read_data()
    group = get_group_by_id(group_id)
    if not group or current_user['id'] not in group['members']:
        raise HTTPException(status_code=404, detail="Group not found or access denied")
    # Count total pins for user (chats + groups)
    total_pins = 0
    for c in db['chats']:
        if current_user['id'] in c.get('pinned', []):
            total_pins += 1
    if total_pins >= 5:
        raise HTTPException(status_code=400, detail="Max 5 pins allowed")
    if current_user['id'] not in group['pinned']:
        group['pinned'].append(current_user['id'])
        write_data(db)
    return {"msg": "Group pinned"}

@app.post('/groups/{group_id}/archive')
def archive_group(group_id: int, current_user: dict = Depends(get_current_user)):
    db = read_data()
    group = get_group_by_id(group_id)
    if not group or current_user['id'] not in group['members']:
        raise HTTPException(status_code=404, detail="Group not found or access denied")
    if current_user['id'] not in group['archived']:
        group['archived'].append(current_user['id'])
        write_data(db)
    return {"msg": "Group archived"}

@app.delete('/groups/{group_id}')
def delete_group(group_id: int, current_user: dict = Depends(get_current_user)):
    db = read_data()
    group = get_group_by_id(group_id)
    if not group or current_user['id'] not in group['admins']:
        raise HTTPException(status_code=403, detail="Only admins can delete group")
    db['chats'] = [c for c in db['chats'] if c.get('id') != group_id]
    write_data(db)
    return {"msg": "Group deleted"}

# --- Health Check ---
@app.get('/health')
def health_check():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

# --- Root endpoint ---
@app.get('/')
def root():
    return {
        "message": "React Native Chat API",
        "version": "1.0.0",
        "docs": "/docs"
    }

# --- In-memory connection manager for WebSocket demo ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict = {}  # chat_id: set of websockets

    async def connect(self, chat_id: int, websocket: WebSocket):
        await websocket.accept()
        if chat_id not in self.active_connections:
            self.active_connections[chat_id] = set()
        self.active_connections[chat_id].add(websocket)

    def disconnect(self, chat_id: int, websocket: WebSocket):
        if chat_id in self.active_connections:
            self.active_connections[chat_id].discard(websocket)
            if not self.active_connections[chat_id]:
                del self.active_connections[chat_id]

    async def broadcast(self, chat_id: int, message: dict):
        if chat_id in self.active_connections:
            for connection in self.active_connections[chat_id]:
                await connection.send_json(message)

manager = ConnectionManager()

@app.websocket('/ws/chat/{chat_id}')
async def websocket_chat(websocket: WebSocket, chat_id: int):
    # For demo: no auth, but you can add token query param and verify
    await manager.connect(chat_id, websocket)
    try:
        while True:
            data = await websocket.receive_json()
            if data.get("type") == "typing":
                typing_msg = {
                    "type": "typing",
                    "user_id": data.get("user_id"),
                    "chat_id": chat_id
                }
                # Only send to others, not the sender
                for ws in manager.active_connections.get(chat_id, []):
                    if ws != websocket:
                        await ws.send_json(typing_msg)
                continue
            # Expect: {"sender_id": int, "content": str, "mentions": [int]}
            sender_id = data.get('sender_id')
            content = data.get('content')
            mentions = data.get('mentions', [])
            db = read_data()
            chat = get_chat_by_id(chat_id)
            if not chat or sender_id not in chat['members']:
                await websocket.send_json({"error": "Chat not found or access denied"})
                continue
            msg_id = str(uuid4())
            message = {
                'id': msg_id,
                'sender_id': sender_id,
                'content': content,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'deleted_for': [],
                'deleted_for_everyone': False,
                'mentions': mentions
            }
            chat['messages'].append(message)
            # Update unread counts for other members
            for uid in chat['members']:
                if uid != sender_id:
                    chat['unread_counts'][str(uid)] = chat['unread_counts'].get(str(uid), 0) + 1
            write_data(db)
            await manager.broadcast(chat_id, message)
    except WebSocketDisconnect:
        manager.disconnect(chat_id, websocket)

# --- Tagging: Get all messages where current user is mentioned ---
@app.get('/chats/{chat_id}/mentions')
def get_mentions(chat_id: int, current_user: dict = Depends(get_current_user)):
    chat = get_chat_by_id(chat_id)
    if not chat or current_user['id'] not in chat['members']:
        raise HTTPException(status_code=404, detail="Chat not found or access denied")
    tagged_msgs = [msg for msg in chat['messages'] if 'mentions' in msg and current_user['id'] in msg['mentions']]
    return tagged_msgs