import os
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, status, APIRouter, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from jose import JWTError, jwt
import sqlite3
from datetime import datetime, timedelta
from passlib.context import CryptContext


# Constants for JWT
SECRET_KEY = "YOUR_SECRET_KEY"  # Replace with env variable in production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DATABASE_PATH = os.environ.get("SQLITE_PATH", "./db.sqlite3")

openapi_tags = [
    {"name": "Authentication", "description": "User sign up/in, OAuth, JWT session management."},
    {"name": "User", "description": "User profile, settings, dashboard."},
    {"name": "Wellness", "description": "Diet, fitness, mindfulness, sleep features."},
    {"name": "SustainableLiving",
     "description": "Product scanner, business directory, carbon tracker."},
    {"name": "ChronicDisease", "description": "Dashboards for diabetes etc."},
    {"name": "TeleConsultation", "description": "Consultation booking, session, prescription."},
    {"name": "Community", "description": "Forums, events, peer groups, map resources."},
    {"name": "Education", "description": "Articles, videos, hub."},
    {"name": "AI", "description": "AI assistant chat endpoints."},
    {"name": "HealthCheck", "description": "Database and app status."},
]


app = FastAPI(
    title="ArogyaMitr Backend API",
    description="REST API backend for ArogyaMitr health and wellness app.",
    version="1.0.0",
    openapi_tags=openapi_tags,
)


# CORS middleware setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# SQLite utility
def get_db():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# Models ====================================================

# PUBLIC_INTERFACE
class UserRegister(BaseModel):
    """User registration model."""
    email: Optional[EmailStr] = Field(None, description="Email address for signup")
    phone: Optional[str] = Field(None, description="Phone number for signup")
    password: str = Field(..., description="Account password; hashed on server")


# PUBLIC_INTERFACE
class UserLogin(BaseModel):
    email: Optional[EmailStr] = Field(None, description="Email for login")
    phone: Optional[str] = Field(None, description="Phone for login")
    password: str = Field(..., description="Account password")


# PUBLIC_INTERFACE
class Token(BaseModel):
    """JWT token model."""
    access_token: str
    token_type: str


class ProfileSettings(BaseModel):
    """User profile and settings."""
    name: str
    avatar_url: Optional[str] = None
    date_of_birth: Optional[str] = None
    gender: Optional[str] = None
    # More fields as required


class DietPlan(BaseModel):
    """Diet/Nutrition plan for user."""
    plan_name: str
    calories: int
    meals: List[str]


class FitnessActivity(BaseModel):
    """Fitness activity log."""
    activity: str
    duration_minutes: int
    calories_burned: int


class MindfulnessEntry(BaseModel):
    """Mindfulness log entry."""
    date: str
    mood: str
    journal: str


class SleepRecord(BaseModel):
    """Sleep record."""
    date: str
    hours: float
    quality: str


class SustainableLivingProduct(BaseModel):
    """Product for sustainable living scanner."""
    upc: str
    name: str
    eco_rating: int


class CarbonEntry(BaseModel):
    """Carbon tracker entry."""
    date: str
    activity: str
    carbon_footprint: float


class ChronicDiseaseData(BaseModel):
    """Chronic disease dashboard data (e.g., diabetes)."""
    type: str
    values: dict


class TeleConsultationBooking(BaseModel):
    """Tele-consultation booking."""
    doctor_id: int
    booked_for: str
    notes: Optional[str] = None


class CommunityPost(BaseModel):
    """Community post."""
    title: str
    body: str
    posted_at: datetime


class EducationItem(BaseModel):
    """Educational content entry."""
    title: str
    url: str
    type: str  # 'article' or 'video'


class AIChatMessage(BaseModel):
    """AI Bot message."""
    message: str


# AUTHENTICATION & SECURITY =================================

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Initialize database (idempotent)
def ensure_tables():
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            phone TEXT UNIQUE,
            hashed_password TEXT,
            name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )"""
        )
        # Add more tables for each module as needed
        conn.commit()


ensure_tables()


# Token utility
def create_access_token(data: dict, expires_delta: timedelta = None):
    """Generate JWT token for session."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password):
    return pwd_context.hash(password)


def get_user_by_email(conn, email):
    row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    return row


def get_user_by_phone(conn, phone):
    row = conn.execute("SELECT * FROM users WHERE phone=?", (phone,)).fetchone()
    return row


def authenticate_user(conn, email: Optional[str], phone: Optional[str], password: str):
    user = None
    if email:
        user = get_user_by_email(conn, email)
    elif phone:
        user = get_user_by_phone(conn, phone)
    if user:
        if verify_password(password, user["hashed_password"]):
            return user
    return None


# API ROUTERS ===============================================

auth_router = APIRouter(prefix="/auth", tags=["Authentication"])


# PUBLIC_INTERFACE
@auth_router.post("/register", summary="Register a new user", response_model=Token)
def register_user(payload: UserRegister, db=Depends(get_db)):
    """Register user via email or phone and return JWT session token."""
    if not (payload.email or payload.phone):
        raise HTTPException(status_code=400, detail="Provide email or phone.")
    existing = None
    if payload.email:
        existing = get_user_by_email(db, payload.email)
    elif payload.phone:
        existing = get_user_by_phone(db, payload.phone)
    if existing:
        raise HTTPException(status_code=400, detail="User already exists.")

    hashed_password = hash_password(payload.password)
    try:
        db.execute(
            "INSERT INTO users (email, phone, hashed_password) VALUES (?, ?, ?)",
            (payload.email, payload.phone, hashed_password),
        )
        db.commit()
        if payload.email:
            user_query = get_user_by_email(db, payload.email)
        else:
            user_query = get_user_by_phone(db, payload.phone)
        access_token = create_access_token(
            data={"sub": str(user_query["id"])}
        )
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception:
        raise HTTPException(status_code=500, detail="Registration failed")


# PUBLIC_INTERFACE
@auth_router.post("/token", summary="Obtain JWT token for login", response_model=Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db=Depends(get_db)
):
    """Authenticate via email/password or phone/password and return JWT token."""
    user = None
    if form_data.username and ("@" in form_data.username):
        user = authenticate_user(db, form_data.username, None, form_data.password)
    else:
        user = authenticate_user(db, None, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect credentials")
    access_token = create_access_token(data={"sub": str(user["id"])})
    return {"access_token": access_token, "token_type": "bearer"}


# PUBLIC_INTERFACE
@auth_router.post("/oauth", summary="OAuth login/sign-up (Google/Apple)", response_model=Token)
def oauth_login(
    provider: str = Body(..., embed=True), token: str = Body(...), db=Depends(get_db)
):
    """
    Exchange OAuth token for ArogyaMitr JWT (mock endpoint, demo only).
    """
    # For demonstration, just accept input and return a dummy JWT
    # In real scenario validate the OAuth token with provider!
    fake_id = "oauthuser_" + provider
    access_token = create_access_token(data={"sub": fake_id, "oauth_provider": provider})
    return {"access_token": access_token, "token_type": "bearer"}


# JWT-authenticated User dependency
def get_current_user(token: str = Depends(oauth2_scheme), db=Depends(get_db)):
    """Get currently authenticated user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: Optional[str] = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    # Fetch user from DB (could be OAuth user)
    user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user and str(user_id).startswith("oauthuser_"):
        # Simulate for demo OAuth users
        return {"id": user_id, "email": None}
    elif not user:
        raise credentials_exception
    return user


# PUBLIC_INTERFACE
@app.get("/health/db", tags=["HealthCheck"], summary="DB health check")
def db_health_check():
    """
    Database health check endpoint.

    Returns database connection status and version.
    """
    try:
        with sqlite3.connect(DATABASE_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT sqlite_version();")
            version = cursor.fetchone()
        return {"status": "ok", "sqlite_version": version[0]}
    except Exception:
        return JSONResponse(
            status_code=500,
            content={"status": "error", "error": "DB unreachable"},
        )


# Example protected user endpoint
user_router = APIRouter(prefix="/user", tags=["User"])


# PUBLIC_INTERFACE
@user_router.get("/profile", summary="Get user profile", response_model=ProfileSettings)
def get_profile(current_user=Depends(get_current_user)):
    """Return the current user's profile and settings."""
    # Placeholder values; would use DB records
    name_value = (
        current_user.get("name")
        if isinstance(current_user, dict)
        else current_user["name"]
    )
    return ProfileSettings(
        name=name_value,
        avatar_url=None,
        date_of_birth=None,
        gender=None,
    )


# Modular route placeholders for core modules ===================

wellness_router = APIRouter(prefix="/wellness", tags=["Wellness"])
sustainable_router = APIRouter(prefix="/sustainable", tags=["SustainableLiving"])
chronic_router = APIRouter(prefix="/chronic", tags=["ChronicDisease"])
teleconsult_router = APIRouter(prefix="/teleconsult", tags=["TeleConsultation"])
community_router = APIRouter(prefix="/community", tags=["Community"])
education_router = APIRouter(prefix="/education", tags=["Education"])
ai_router = APIRouter(prefix="/ai", tags=["AI"])


# Diet/Nutrition endpoint
# PUBLIC_INTERFACE
@wellness_router.get("/diet/plan", summary="Get user's diet plan", response_model=DietPlan)
def get_diet_plan(current_user=Depends(get_current_user)):
    """Get the personalized diet plan for the current user."""
    # Demo response only
    return DietPlan(
        plan_name="Balanced Plan",
        calories=2000,
        meals=["Breakfast", "Lunch", "Dinner"],
    )


# Fitness endpoint
@wellness_router.get(
    "/fitness/activities",
    summary="Get user's fitness activities",
    response_model=List[FitnessActivity],
)
def get_fitness_activities(current_user=Depends(get_current_user)):
    """List fitness activities for user."""
    # Demo response
    return [
        FitnessActivity(
            activity="Walking",
            duration_minutes=45,
            calories_burned=180,
        )
    ]


# Mindfulness endpoint
@wellness_router.get(
    "/mindfulness/journal",
    summary="Get user's mindfulness journal",
    response_model=List[MindfulnessEntry],
)
def get_mindfulness_journal(current_user=Depends(get_current_user)):
    """Return all mindfulness journal entries."""
    return [
        MindfulnessEntry(
            date=str(datetime.now().date()),
            mood="Positive",
            journal="Felt calm after meditation.",
        )
    ]


# Sleep endpoint
@wellness_router.get(
    "/sleep/records",
    summary="Get user's sleep records",
    response_model=List[SleepRecord],
)
def get_sleep_records(current_user=Depends(get_current_user)):
    """Get the user's sleep records."""
    return [
        SleepRecord(
            date=str(datetime.now().date()),
            hours=7.2,
            quality="Good",
        )
    ]


# Sustainable Living
@sustainable_router.get(
    "/product/scan",
    summary="Scan product UPC for eco info",
    response_model=SustainableLivingProduct,
)
def product_scan(upc: str):
    """Scan product UPC for sustainability info."""
    return SustainableLivingProduct(
        upc=upc, name="Demo Product", eco_rating=4
    )


@sustainable_router.get(
    "/business/directory",
    summary="List businesses",
    response_model=List[str],
)
def list_businesses():
    """Return a list of sustainable businesses."""
    return ["EcoMart", "GreenLife Store", "Solar Home"]


@sustainable_router.get(
    "/carbon/tracker",
    summary="Get carbon entries",
    response_model=List[CarbonEntry],
)
def get_carbon_entries(current_user=Depends(get_current_user)):
    """Get carbon tracker entries for user."""
    return [
        CarbonEntry(
            date=str(datetime.now().date()),
            activity="Cycling",
            carbon_footprint=0.1,
        )
    ]


# Chronic Disease
@chronic_router.get(
    "/dashboard",
    summary="Get chronic disease dashboard",
    response_model=ChronicDiseaseData,
)
def get_chronic_dashboard(current_user=Depends(get_current_user)):
    """Return dashboard data for a chronic disease."""
    return ChronicDiseaseData(
        type="diabetes",
        values={"hba1c": 6.7, "last_reading": "normal"},
    )


# Teleconsultation
@teleconsult_router.post(
    "/booking",
    summary="Book a tele-consultation",
    response_model=dict,
)
def book_consultation(payload: TeleConsultationBooking, current_user=Depends(get_current_user)):
    """Create a consultation booking request."""
    return {
        "status": "booked",
        "doctor_id": payload.doctor_id,
        "booked_for": payload.booked_for,
    }


@teleconsult_router.get(
    "/prescriptions",
    summary="Get prescriptions",
    response_model=List[str],
)
def get_prescriptions(current_user=Depends(get_current_user)):
    """Get user's prescriptions from teleconsultation."""
    return ["Prescription1.pdf", "Prescription2.pdf"]


# Community
@community_router.get(
    "/posts",
    summary="List community posts",
    response_model=List[CommunityPost],
)
def list_posts():
    """List recent community posts."""
    now = datetime.now()
    return [
        CommunityPost(
            title="Welcome!",
            body="This is the forum.",
            posted_at=now,
        )
    ]


# Education
@education_router.get(
    "/content",
    summary="Get education articles/videos",
    response_model=List[EducationItem],
)
def get_education_content():
    """Return education hub entries."""
    return [
        EducationItem(
            title="Healthy Eating Tips",
            url="https://health.example.com/tips",
            type="article",
        ),
        EducationItem(
            title="Yoga Routine",
            url="https://video.example.com/yoga",
            type="video",
        ),
    ]


# AI Chat
@ai_router.post(
    "/chat",
    summary="Send message to health AI",
    response_model=AIChatMessage,
)
def ai_chat(msg: AIChatMessage, current_user=Depends(get_current_user)):
    """AI health assistant chat endpoint (mock: echo)."""
    # Replace with actual AI service integration in production
    return AIChatMessage(message=f"AI says: {msg.message}")


# ROUTE REGISTRATION
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(wellness_router)
app.include_router(sustainable_router)
app.include_router(chronic_router)
app.include_router(teleconsult_router)
app.include_router(community_router)
app.include_router(education_router)
app.include_router(ai_router)


# Swagger WebSocket help route (for reference, AI chat in prod could support websocket)
@app.get(
    "/docs/websocket",
    tags=["AI"],
    summary="WebSocket AI chat usage",
    include_in_schema=False,
)
def websocket_usage():
    """WebSocket usage note for future AI endpoints."""
    return {
        "message": (
            "AI chat endpoint for WebSocket will be /ws/ai in future "
            "for real-time assistance (not implemented)."
        )
    }


# Default root health check (overrides template)
@app.get("/", summary="App health check", tags=["HealthCheck"])
def health_check():
    """Simple application health check (not DB)."""
    return {"message": "Healthy"}
