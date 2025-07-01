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


# PUBLIC_INTERFACE
class ProfileSettings(BaseModel):
    """User profile and settings information."""
    name: Optional[str] = Field(..., description="Full name of the user")
    avatar_url: Optional[str] = Field(
        None, description="URL to profile avatar"
    )
    date_of_birth: Optional[str] = Field(
        None, description="Date of birth of the user (YYYY-MM-DD)"
    )
    gender: Optional[str] = Field(
        None, description="Gender identity"
    )
    address: Optional[str] = Field(
        None, description="Physical address, if available"
    )
    bio: Optional[str] = Field(
        None, description="Short bio or health goals"
    )
    preferences: Optional[dict] = Field(
        default_factory=dict,
        description="Custom notification/settings preferences"
    )


# PUBLIC_INTERFACE
class DietMeal(BaseModel):
    """Individual meal entry for a diet plan."""
    name: str = Field(..., description="Name of the meal")
    calories: int = Field(..., description="Total calorie count for the meal")
    time: Optional[str] = Field(None, description="Suggested meal time (e.g. breakfast)")


# PUBLIC_INTERFACE
class DietPlan(BaseModel):
    """Diet/Nutrition plan assigned to a user. Use for CRUD."""
    id: Optional[int] = Field(None, description="Record ID for update/read")
    user_id: int = Field(..., description="User ID this plan belongs to")
    plan_name: str = Field(..., description="Name for the diet plan")
    calories: int = Field(..., description="Total calories per day")
    meals: List[DietMeal] = Field(
        ..., description="List of meals for the plan"
    )
    notes: Optional[str] = Field(
        None, description="Special dietary notes"
    )


# PUBLIC_INTERFACE
class FitnessActivity(BaseModel):
    """Fitness activity log entry."""
    id: Optional[int] = Field(None, description="Record ID for update/read")
    user_id: int = Field(..., description="User ID logging this activity")
    activity: str = Field(
        ..., description="Name/type of activity (e.g. Running, Yoga)"
    )
    duration_minutes: int = Field(
        ..., description="Duration in minutes"
    )
    calories_burned: int = Field(
        ..., description="Calories burned"
    )
    timestamp: Optional[str] = Field(
        None, description="Date/time of activity"
    )


# PUBLIC_INTERFACE
class MindfulnessEntry(BaseModel):
    """Mindfulness journal entry."""
    id: Optional[int] = Field(None, description="Record ID for update/read")
    user_id: int = Field(..., description="User ID who made this entry")
    date: str = Field(..., description="Journal entry date (YYYY-MM-DD)")
    mood: str = Field(..., description="User's mood/emotion for the entry")
    journal: str = Field(..., description="Text content of the mindfulness/journal entry")


# PUBLIC_INTERFACE
class SleepRecord(BaseModel):
    """Sleep record log."""
    id: Optional[int] = Field(None, description="Record ID for update/read")
    user_id: int = Field(..., description="User ID for sleep data")
    date: str = Field(..., description="Date of the sleep record (YYYY-MM-DD)")
    hours: float = Field(..., description="Sleep duration in hours")
    quality: str = Field(..., description="Quality of sleep (Good/Moderate/Poor)")
    notes: Optional[str] = Field(None, description="Additional notes")


# PUBLIC_INTERFACE
class SustainableLivingProduct(BaseModel):
    """Product for sustainable living scanner."""
    id: Optional[int] = Field(None, description="Record ID for update/read")
    upc: str = Field(..., description="UPC code of the product")
    name: str = Field(..., description="Product name")
    eco_rating: int = Field(..., description="Eco sustainability rating (1-5)")
    verified: Optional[bool] = Field(False, description="Is this product eco-verified?")


# PUBLIC_INTERFACE
class SustainableBusiness(BaseModel):
    """Directory entry for a sustainable business."""
    id: Optional[int] = Field(None)
    name: str = Field(..., description="Name of the business")
    category: str = Field(..., description="Type/category, e.g. Grocery, Retail, Service")
    address: str = Field(..., description="Address of the business")
    website: Optional[str] = Field(None, description="Website link")
    phone: Optional[str] = Field(None, description="Contact phone")


# PUBLIC_INTERFACE
class CarbonEntry(BaseModel):
    """Carbon tracker log."""
    id: Optional[int] = Field(None, description="Record ID for update/read")
    user_id: int = Field(..., description="User ID for log")
    date: str = Field(..., description="Date (YYYY-MM-DD)")
    activity: str = Field(..., description="Activity description")
    carbon_footprint: float = Field(..., description="CO2 in kg")


# PUBLIC_INTERFACE
class ChronicDiseaseData(BaseModel):
    """Chronic disease indicator for user (support multiple diseases)."""
    id: Optional[int] = Field(None)
    user_id: int = Field(..., description="User ID this data belongs to")
    disease_type: str = Field(
        ..., description="Disease type (e.g. diabetes, hypertension)"
    )
    recorded_date: str = Field(
        ..., description="Date of observation (YYYY-MM-DD)"
    )
    metrics: dict = Field(
        ..., description="Arbitrary metric dict (hba1c, bp, etc.)"
    )
    medications: Optional[str] = Field(
        None, description="Current medications, comma separated"
    )
    notes: Optional[str] = Field(
        None, description="Notes/reminders"
    )


# PUBLIC_INTERFACE
class TeleConsultationBooking(BaseModel):
    """Tele-consultation booking."""
    id: Optional[int] = Field(None)
    user_id: int = Field(..., description="User ID booking the consultation")
    doctor_id: int = Field(..., description="Doctor ID")
    booked_for: str = Field(..., description="Appointment time or slot")
    status: str = Field(..., description="Current status (booked, completed, cancelled)")
    notes: Optional[str] = Field(None, description="Optional notes")
    prescription_file: Optional[str] = Field(None, description="Path/URL to associated prescription file")


# PUBLIC_INTERFACE
class CommunityPost(BaseModel):
    """Community post or forum entry."""
    id: Optional[int] = Field(None)
    user_id: int = Field(..., description="User ID posting")
    title: str = Field(..., description="Post title")
    body: str = Field(..., description="Content of the community post")
    posted_at: str = Field(
        ...,
        description=(
            "Posting datetime ISO8601"
        )
    )
    tags: Optional[List[str]] = Field(
        default_factory=list, description="Tags/labels"
    )


# PUBLIC_INTERFACE
class CommunityEvent(BaseModel):
    """Community health/local event."""
    id: Optional[int] = Field(None)
    title: str = Field(..., description="Event name/title")
    description: str = Field(..., description="Event details")
    date: str = Field(..., description="Event date (YYYY-MM-DD)")
    location: str = Field(..., description="Event location, use city/locality")
    organizer: Optional[str] = Field(None, description="Event organizer")
    url: Optional[str] = Field(None, description="Link for more info")


# PUBLIC_INTERFACE
class EducationItem(BaseModel):
    """Educational content: articles/videos."""
    id: Optional[int] = Field(None)
    title: str = Field(..., description="Title for this content")
    url: str = Field(..., description="URL or video link")
    type: str = Field(..., description="'article' or 'video'")
    topic: Optional[str] = Field(None, description="For search/filtering (e.g. fitness)")
    summary: Optional[str] = Field(None, description="Short summary/abstract")


# PUBLIC_INTERFACE
class AIChatMessage(BaseModel):
    """AI Bot message."""
    id: Optional[int] = Field(None)
    user_id: int = Field(..., description="User ID (for chat persistence/history)")
    message: str = Field(..., description="Message from/to AI bot")
    sender: str = Field(..., description="'user' or 'ai'")
    timestamp: Optional[str] = Field(None, description="Message timestamp ISO8601")
    session_id: Optional[str] = Field(None, description="Session/grouping key for chat")


# AUTHENTICATION & SECURITY =================================

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# Initialize database (idempotent)
def ensure_tables():
    with sqlite3.connect(DATABASE_PATH) as conn:
        cursor = conn.cursor()
        # User table
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
        # Profile settings table
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS profiles (
            user_id INTEGER PRIMARY KEY,
            avatar_url TEXT,
            date_of_birth TEXT,
            gender TEXT,
            address TEXT,
            bio TEXT,
            preferences TEXT DEFAULT '{}',
            FOREIGN KEY (user_id) REFERENCES users(id)
        )"""
        )
        # Diet plans
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS diet_plans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            plan_name TEXT,
            calories INTEGER,
            notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )"""
        )
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS diet_meals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plan_id INTEGER,
            name TEXT,
            calories INTEGER,
            time TEXT,
            FOREIGN KEY (plan_id) REFERENCES diet_plans(id)
        )"""
        )
        # Fitness
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS fitness_activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            activity TEXT,
            duration_minutes INTEGER,
            calories_burned INTEGER,
            timestamp TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )"""
        )
        # Mindfulness
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS mindfulness_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            date TEXT,
            mood TEXT,
            journal TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )"""
        )
        # Sleep
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS sleep_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            date TEXT,
            hours REAL,
            quality TEXT,
            notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )"""
        )
        # Sustainable products
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS sustainable_products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            upc TEXT UNIQUE,
            name TEXT,
            eco_rating INTEGER,
            verified INTEGER DEFAULT 0
        )"""
        )
        # Sustainable businesses
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS sustainable_businesses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            category TEXT,
            address TEXT,
            website TEXT,
            phone TEXT
        )"""
        )
        # Carbon tracker
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS carbon_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            date TEXT,
            activity TEXT,
            carbon_footprint REAL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )"""
        )
        # Chronic disease indicators
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS chronic_disease_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            disease_type TEXT,
            recorded_date TEXT,
            metrics TEXT,
            medications TEXT,
            notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )"""
        )
        # Tele-consultation bookings
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS teleconsult_bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            doctor_id INTEGER,
            booked_for TEXT,
            status TEXT,
            notes TEXT,
            prescription_file TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )"""
        )
        # Community posts
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS community_posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            body TEXT,
            posted_at TEXT,
            tags TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )"""
        )
        # Community events
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS community_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            description TEXT,
            date TEXT,
            location TEXT,
            organizer TEXT,
            url TEXT
        )"""
        )
        # Education hub
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS education_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            url TEXT,
            type TEXT,
            topic TEXT,
            summary TEXT
        )"""
        )
        # AI chat messages
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS ai_chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            message TEXT,
            sender TEXT,
            timestamp TEXT,
            session_id TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )"""
        )
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