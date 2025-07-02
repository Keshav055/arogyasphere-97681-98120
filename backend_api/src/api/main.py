"""
ArogyaMitr FastAPI Backend
- Modular app structure with routers for key features
- SQLite database integration via SQLAlchemy
- JWT authentication, OAuth stub, role-based access
- Example endpoints for all modules (stubs where complex integration needed)
- /health/db endpoint to verify DB status
- Ready for extension
"""

from fastapi import FastAPI, Depends, HTTPException, status, APIRouter, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Any, Dict
from datetime import datetime, timedelta
from jose import JWTError, jwt
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
import sqlite3
import logging

# === CONFIGURATION ===
DATABASE_URL = "sqlite:///./arogyamitr.db"
SECRET_KEY = "supersecretkeypleasechange" # Replace for production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# === DB SETUP ===
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# === LOGGER ===
logger = logging.getLogger("arogyamitr")
logging.basicConfig(level=logging.INFO)

# === MODELS (SQLAlchemy) ===
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    phone = Column(String, unique=True, nullable=True)
    hashed_password = Column(String, nullable=False)
    full_name = Column(String)
    role = Column(String, default="user")  # user, doctor, admin
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    action = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)
    detail = Column(Text)

# Sample tables for features (expand as needed)
class DietLog(Base):
    __tablename__ = "diet_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    date = Column(DateTime, default=datetime.utcnow)
    description = Column(Text)

class FitnessLog(Base):
    __tablename__ = "fitness_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    activity = Column(String)
    duration = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)

class MindfulnessLog(Base):
    __tablename__ = "mindfulness_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    mood = Column(String)
    note = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

class SleepLog(Base):
    __tablename__ = "sleep_logs"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    hours = Column(Integer)
    sleep_quality = Column(String)
    timestamp = Column(DateTime, default=datetime.utcnow)

class DiseaseDashboard(Base):
    __tablename__ = "disease_dashboards"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    disease = Column(String)
    details = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

# Additional tables (forum posts, teleconsult, education, AI chat logs) can be added similarly.

# === DB INIT ===
def init_db():
    Base.metadata.create_all(bind=engine)
init_db()

# === Pydantic MODELS ===
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None

class UserCreate(UserBase):
    password: str

class UserOut(UserBase):
    id: int
    role: str
    is_active: bool

    class Config:
        orm_mode = True

# === AUTH & ROLE UTILS ===
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")

# PUBLIC_INTERFACE
def verify_password(plain_password, hashed_password):
    """Verify password, using plain == hash for demo. Replace with secure hash in prod."""
    return plain_password == hashed_password

# PUBLIC_INTERFACE
def fake_hash_password(password: str):
    """Stub for hash password. In prod use bcrypt/argon2/etc."""
    return password + "notreallyhashed"

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def get_user_by_phone(db: Session, phone: str):
    return db.query(User).filter(User.phone == phone).first()

def log_audit(db: Session, action: str, user_id: Optional[int] = None, detail: Optional[str] = None):
    db_log = AuditLog(user_id=user_id, action=action, detail=detail)
    db.add(db_log)
    db.commit()

# PUBLIC_INTERFACE
def authenticate_user(db: Session, email: str, password: str):
    """Authenticate user with email and password"""
    user = get_user_by_email(db, email)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user

# PUBLIC_INTERFACE
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# PUBLIC_INTERFACE
async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Get current user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    db = SessionLocal()
    user = get_user_by_email(db, email=token_data.email)
    db.close()
    if user is None:
        raise credentials_exception
    return user

# PUBLIC_INTERFACE
def get_current_active_user(current_user: User = Depends(get_current_user)):
    """Checks for active user."""
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# PUBLIC_INTERFACE
def require_roles(roles: List[str]):
    """Role-based dependency"""

    def wrapper(current_user: User = Depends(get_current_active_user)):
        if current_user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient privileges"
            )
        return current_user
    return wrapper

# === FASTAPI APP ===
app = FastAPI(
    title="ArogyaMitr Backend API",
    version="1.0.0",
    description="API for ArogyaMitr: Holistic Indian Wellness Platform",
    openapi_tags=[
        {"name": "auth", "description": "Authentication & Authorization"},
        {"name": "users", "description": "User profile and settings"},
        {"name": "diet", "description": "Diet, nutrition & hydration"},
        {"name": "fitness", "description": "Fitness logs & recommendations"},
        {"name": "mindfulness", "description": "Mindfulness tools"},
        {"name": "sleep", "description": "Sleep tracking"},
        {"name": "living", "description": "Conscious/Sustainable Living"},
        {"name": "disease", "description": "Chronic Disease Dashboards"},
        {"name": "teleconsult", "description": "Tele-consultation"},
        {"name": "forum", "description": "Community Forums"},
        {"name": "education", "description": "Education Hub"},
        {"name": "ai_chat", "description": "AI Health Chatbot"},
        {"name": "utils", "description": "Utilities and health checks"},
    ]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"], allow_credentials=True,
)

# --- DEPENDENCY ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# === ROUTERS ===

auth_router = APIRouter(prefix="/auth", tags=["auth"])
users_router = APIRouter(prefix="/users", tags=["users"])
diet_router = APIRouter(prefix="/diet", tags=["diet"])
fitness_router = APIRouter(prefix="/fitness", tags=["fitness"])
mindfulness_router = APIRouter(prefix="/mindfulness", tags=["mindfulness"])
sleep_router = APIRouter(prefix="/sleep", tags=["sleep"])
living_router = APIRouter(prefix="/living", tags=["living"])
disease_router = APIRouter(prefix="/disease", tags=["disease"])
teleconsult_router = APIRouter(prefix="/teleconsult", tags=["teleconsult"])
forum_router = APIRouter(prefix="/forum", tags=["forum"])
education_router = APIRouter(prefix="/education", tags=["education"])
ai_chat_router = APIRouter(prefix="/ai-chat", tags=["ai_chat"])
utils_router = APIRouter(tags=["utils"])

# --- AUTH ROUTES ---
@auth_router.post("/signup", response_model=UserOut, summary="Register new user")
def signup(user_in: UserCreate, db: Session = Depends(get_db)):
    """User registration using email. Demo: plain password (replace in prod)."""
    db_user = get_user_by_email(db, user_in.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_obj = User(
        email=user_in.email,
        hashed_password=fake_hash_password(user_in.password),
        full_name=user_in.full_name,
    )
    db.add(user_obj)
    db.commit()
    db.refresh(user_obj)
    log_audit(db, action="signup", user_id=user_obj.id)
    return user_obj

@auth_router.post("/token", response_model=Token, summary="Login and get JWT token")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """Login using OAuth2PasswordRequestForm. Demo logic."""
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(
        data={"sub": user.email, "role": user.role},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    log_audit(db, action="login", user_id=user.id)
    return {"access_token": access_token, "token_type": "bearer"}

@auth_router.post("/oauth-demo", summary="OAuth social login STUB")
def oauth_stub(provider: str):
    """Stub for Google/Apple OAuth, replace with real integration."""
    return {"message": f"OAuth sign-in/up with {provider} not implemented, demo only."}

# --- USER ROUTES ---
@users_router.get("/me", response_model=UserOut, summary="Get my profile")
def get_me(current_user: User = Depends(get_current_active_user)):
    """Returns current user's profile."""
    return current_user

@users_router.get("/{user_id}", response_model=UserOut, summary="Get user by id")
def get_user(user_id: int, db: Session = Depends(get_db), user=Depends(require_roles(["admin"]))):
    """Admin can fetch any user by ID."""
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return u

# --- DIET/NUTRITION ROUTES ---
class DietLogIn(BaseModel):
    description: str

@diet_router.get("/", summary="Get user's diet logs")
def get_diet_logs(current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    logs = db.query(DietLog).filter(DietLog.user_id == current_user.id).all()
    return logs

@diet_router.post("/", summary="Log a diet entry")
def log_diet(log: DietLogIn, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    entry = DietLog(user_id=current_user.id, description=log.description)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry

# --- FITNESS ROUTES ---
class FitnessLogIn(BaseModel):
    activity: str
    duration: int

@fitness_router.get("/", summary="Get fitness logs")
def get_fitness_logs(current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    logs = db.query(FitnessLog).filter(FitnessLog.user_id == current_user.id).all()
    return logs

@fitness_router.post("/", summary="Log a fitness activity")
def log_fitness(fitness: FitnessLogIn, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    entry = FitnessLog(user_id=current_user.id, activity=fitness.activity, duration=fitness.duration)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry

# --- MINDFULNESS ROUTES ---
class MindfulnessLogIn(BaseModel):
    mood: str
    note: Optional[str] = None

@mindfulness_router.get("/", summary="Get mindfulness logs")
def get_mindfulness_logs(current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    logs = db.query(MindfulnessLog).filter(MindfulnessLog.user_id == current_user.id).all()
    return logs

@mindfulness_router.post("/", summary="Log a mindfulness entry")
def log_mindfulness(data: MindfulnessLogIn, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    entry = MindfulnessLog(user_id=current_user.id, mood=data.mood, note=data.note)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry

# --- SLEEP ROUTES ---
class SleepLogIn(BaseModel):
    hours: int
    sleep_quality: str

@sleep_router.get("/", summary="Get sleep logs")
def get_sleep_logs(current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    logs = db.query(SleepLog).filter(SleepLog.user_id == current_user.id).all()
    return logs

@sleep_router.post("/", summary="Log sleep data")
def log_sleep(data: SleepLogIn, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    entry = SleepLog(user_id=current_user.id, hours=data.hours, sleep_quality=data.sleep_quality)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry

# --- LIVING ROUTES (STUB) ---
@living_router.get("/", summary="Get conscious living data")
def get_living():
    return {"message": "Stub conscious living endpoint"}

# --- CHRONIC DISEASE ROUTES (STUB) ---
@disease_router.get("/", summary="Get disease dashboards")
def get_disease_dashboards():
    return {"message": "Stub dashboards"}

# --- TELE-CONSULT ROUTES (STUB) ---
@teleconsult_router.get("/", summary="List tele-consultation sessions")
def list_sessions():
    return {"message": "Stub teleconsult"}

# --- COMMUNITY FORUM (STUB) ---
@forum_router.get("/", summary="Get forum posts")
def forum_posts():
    return {"message": "Stub forum posts"}

# --- EDUCATION HUB (STUB) ---
@education_router.get("/", summary="List health articles/videos")
def list_education():
    return {"message": "Stub education hub"}

# --- AI CHAT (STUB) ---
@ai_chat_router.post("/", summary="Chat with AI assistant")
def chat_with_ai(input_text: str):
    return {"message": f"AI chat not implemented. You said '{input_text}'"}

# --- UTILS: DB HEALTHCHECK ---
@utils_router.get("/health/db", summary="Check database health")
def db_health():
    try:
        conn = sqlite3.connect("arogyamitr.db")
        conn.execute("SELECT 1")
        conn.close()
        return {"status": "ok"}
    except Exception as ex:
        logger.error("DB health check failed: %s", ex)
        return JSONResponse(status_code=500, content={"status": "error", "detail": str(ex)})

# --- ROOT ENDPOINT (HEALTH) ---
@app.get("/", tags=["utils"])
def health_check():
    return {"message": "Healthy"}

# === REGISTER ROUTERS ===
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(diet_router)
app.include_router(fitness_router)
app.include_router(mindfulness_router)
app.include_router(sleep_router)
app.include_router(living_router)
app.include_router(disease_router)
app.include_router(teleconsult_router)
app.include_router(forum_router)
app.include_router(education_router)
app.include_router(ai_chat_router)
app.include_router(utils_router)

# === CUSTOM OPENAPI to mark stubs ===
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    # Mark stub endpoints in descriptions if needed (optional)
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# === SECURITY: insert an audit log per sensitive action; encrypt data at rest if required (not implemented here, use SQLCipher for prod) ===
