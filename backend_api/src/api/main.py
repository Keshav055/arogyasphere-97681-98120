from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# PUBLIC_INTERFACE
app = FastAPI(
    title="ArogyaMitr API",
    description="Core backend RESTful API for ArogyaMitr: wellness, fitness, nutrition, disease management, AI assistant, and more.",
    version="0.1.0",
    contact={
        "name": "ArogyaMitr Developer Team",
        "email": "support@arogyamitr.example.com",
    }
)

# Add CORS middleware to allow requests from any origin (for dev)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# PUBLIC_INTERFACE
@app.get(
    "/",
    summary="Health check endpoint",
    description="Returns a health status message for the API (for uptime checks, monitoring, etc.)",
    tags=["Health"]
)
def health_check():
    """Basic health check endpoint for service monitoring"""
    return {"message": "Healthy"}
