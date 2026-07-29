import os
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, status, Depends, Security, BackgroundTasks, Query
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from bson import ObjectId
import jwt
import bcrypt

from models import (
    PyObjectId, UserCreate, UserLogin, UserResponse, UserInDB, UserUpdate,
    ProjectCreate, ProjectResponse, ProjectInDB, ProjectUpdate,
    IntegrationCreate, IntegrationUpdate, IntegrationResponse,
    AlertConfigurationCreate, AlertConfigurationUpdate, AlertConfigurationResponse,
    MetricCreate, MetricCreateBatch, MetricResponse, MetricQuery, MetricTrendQuery, MetricTrendResponse,
    Token, TokenData, WebhookPayload
)

# Load environment variables
load_dotenv()

# --- Configuration ---
PLACEHOLDER_API_URL = "http://localhost:8000" # Self-reference URL
APP_NAME = "my-startup"
SERVICE_DESCRIPTION = "Store user profiles, connected API integrations (Vercel, Stripe, GitHub), historical metric data points (timestamp, metric_type, value), and alert configurations. Backend should expose endpoints to ingest metric webhooks, query daily/monthly metric trends, and trigger alert notifications."

# MongoDB Configuration
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "my_startup_db")

# JWT Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

# Admin User Configuration (for potential admin login, though not explicitly in routes)
ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

# Webhook API Key
WEBHOOK_API_KEY = os.getenv("WEBHOOK_API_KEY")

if not JWT_SECRET_KEY:
    raise ValueError("JWT_SECRET_KEY environment variable not set.")
if not WEBHOOK_API_KEY:
    print("WARNING: WEBHOOK_API_KEY environment variable not set. Webhook authentication will fail.")


# --- FastAPI App Setup ---
app = FastAPI(
    title=APP_NAME,
    description=SERVICE_DESCRIPTION,
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Database Connection ---
client: AsyncIOMotorClient = None
db: AsyncIOMotorDatabase = None

@app.on_event("startup")
async def connect_db():
    global client, db
    client = AsyncIOMotorClient(MONGO_URI)
    db = client[DATABASE_NAME]
    print(f"Connected to MongoDB: {MONGO_URI}, Database: {DATABASE_NAME}")

    # Ensure indexes are created
    await create_indexes()

@app.on_event("shutdown")
async def close_db():
    global client
    if client:
        client.close()
        print("Closed MongoDB connection.")

async def get_database() -> AsyncIOMotorDatabase:
    return db

async def create_indexes():
    """Ensures necessary MongoDB indexes are in place."""
    # Users collection
    await db.users.create_index([("email", 1)], unique=True)
    # Projects collection
    await db.projects.create_index([("user_id", 1)])
    # Metrics collection
    await db.metrics.create_index([("project_id", 1), ("timestamp", 1)])
    await db.metrics.create_index([("project_id", 1), ("metric_type", 1), ("timestamp", 1)])
    print("MongoDB indexes ensured.")


# --- Security & Authentication ---

# Password Hashing
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# JWT Token Management
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{PLACEHOLDER_API_URL}/auth/login")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncIOMotorDatabase = Depends(get_database)) -> UserInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
        token_data = TokenData(user_id=PyObjectId(user_id))
    except jwt.PyJWTError:
        raise credentials_exception

    user = await db.users.find_one({"_id": token_data.user_id})
    if user is None:
        raise credentials_exception
    return UserInDB(**user)

async def get_current_admin_user(current_user: UserInDB = Depends(get_current_user)) -> UserInDB:
    if current_user.email != ADMIN_USER: # Simple check, could be role-based
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to perform this action"
        )
    return current_user

# API Key for Webhooks
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_webhook_api_key(api_key: str = Security(api_key_header)):
    if api_key is None or not (api_key == WEBHOOK_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key"
        )
    return api_key


# --- Dependencies for Ownership Checks ---
async def get_project_or_404(
    project_id: PyObjectId,
    current_user: UserInDB = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
) -> ProjectInDB:
    project = await db.projects.find_one({"_id": project_id, "user_id": current_user.id})
    if project is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found or you don't own it")
    return ProjectInDB(**project)


# --- Routers ---
auth_router = APIRouter(prefix="/auth", tags=["Authentication"])
users_router = APIRouter(prefix="/users", tags=["Users"])
projects_router = APIRouter(prefix="/projects", tags=["Projects"])
metrics_router = APIRouter(prefix="/metrics", tags=["Metrics"])
webhooks_router = APIRouter(prefix="/webhooks", tags=["Webhooks"])


# --- Health Check ---
@app.get("/api/health", summary="Health Check", description="Checks the health of the API.")
async def health_check():
    try:
        # Attempt a simple database operation to check connectivity
        await db.command("ping")
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database connection failed: {e}")


# --- Auth Routes ---
@auth_router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED, summary="Registers a new user account.")
async def register_user(user_data: UserCreate, db: AsyncIOMotorDatabase = Depends(get_database)):
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    hashed_password = hash_password(user_data.password)
    user_in_db = UserInDB(
        **user_data.dict(exclude={"password"}),
        password_hash=hashed_password
    )
    new_user = await db.users.insert_one(user_in_db.dict(by_alias=True, exclude={"id"}))
    created_user = await db.users.find_one({"_id": new_user.inserted_id})
    return UserResponse(**created_user)

@auth_router.post("/login", response_model=Token, summary="Authenticates a user and returns an access token.")
async def login_for_access_token(user_data: UserLogin, db: AsyncIOMotorDatabase = Depends(get_database)):
    user = await db.users.find_one({"email": user_data.email})
    if not user or not verify_password(user_data.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user["_id"])}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@auth_router.post("/logout", summary="Invalidates the current user's access token (conceptual for stateless JWT).")
async def logout_user(current_user: UserInDB = Depends(get_current_user)):
    # For stateless JWTs, logout is typically handled client-side by discarding the token.
    # A server-side blacklist could be implemented for more robust invalidation,
    # but it adds complexity. For this exercise, we'll return a success message.
    return {"message": "Successfully logged out (token discarded client-side)."}

@auth_router.get("/me", response_model=UserResponse, summary="Retrieves the profile of the currently authenticated user.")
async def read_users_me(current_user: UserInDB = Depends(get_current_user)):
    return UserResponse(**current_user.dict())


# --- User Routes ---
@users_router.put("/me", response_model=UserResponse, summary="Updates the profile of the currently authenticated user.")
async def update_users_me(user_update: UserUpdate, current_user: UserInDB = Depends(get_current_user), db: AsyncIOMotorDatabase = Depends(get_database)):
    update_data = user_update.dict(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update")

    # If email is being updated, check for uniqueness
    if "email" in update_data and update_data["email"] != current_user.email:
        existing_user = await db.users.find_one({"email": update_data["email"]})
        if existing_user and existing_user["_id"] != current_user.id:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already in use by another user")

    await db.users.update_one({"_id": current_user.id}, {"$set": update_data})
    updated_user = await db.users.find_one({"_id": current_user.id})
    return UserResponse(**updated_user)


# --- Project Routes ---
@projects_router.post("/", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED, summary="Creates a new project for the authenticated user.")
async def create_project(
    project_data: ProjectCreate,
    current_user: UserInDB = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    project_in_db = ProjectInDB(
        **project_data.dict(),
        user_id=current_user.id
    )
    new_project = await db.projects.insert_one(project_in_db.dict(by_alias=True, exclude={"id"}))
    created_project = await db.projects.find_one({"_id": new_project.inserted_id})
    return ProjectResponse(**created_project)

@projects_router.get("/", response_model=List[ProjectResponse], summary="Retrieves a list of all projects owned by the authenticated user.")
async def list_projects(
    current_user: UserInDB = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    projects_cursor = db.projects.find({"user_id": current_user.id})
    projects = await projects_cursor.to_list(length=1000) # Limit to 1000 for now, add pagination if needed
    return [ProjectResponse(**project) for project in projects]

@projects_router.get("/{project_id}", response_model=ProjectResponse, summary="Retrieves details of a specific project.")
async def get_project(project: ProjectInDB = Depends(get_project_or_404)):
    return ProjectResponse(**project.dict())

@projects_router.put("/{project_id}", response_model=ProjectResponse, summary="Updates an existing project.")
async def update_project(
    project_update: ProjectUpdate,
    project: ProjectInDB = Depends(get_project_or_404),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    update_data = project_update.dict(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update")

    await db.projects.update_one({"_id": project.id}, {"$set": update_data})
    updated_project = await db.projects.find_one({"_id": project.id})
    return ProjectResponse(**updated_project)

@projects_router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Deletes a project and all associated data.")
async def delete_project(
    project: ProjectInDB = Depends(get_project_or_404),
    db: AsyncIOMotorDatabase = Depends(get_database),
    background_tasks: BackgroundTasks = None
):
    # Delete associated metrics in the background
    if background_tasks:
        background_tasks.add_task(db.metrics.delete_many, {"project_id": project.id})
    else:
        await db.metrics.delete_many({"project_id": project.id}) # If no background tasks, do it synchronously

    result = await db.projects.delete_one({"_id": project.id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return


# --- Project Integrations Routes ---
@projects_router.post("/{project_id}/integrations", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED, summary="Adds a new API integration to a specific project.")
async def add_integration_to_project(
    project_id: PyObjectId,
    integration_data: IntegrationCreate,
    project: ProjectInDB = Depends(get_project_or_404),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    integration_id = PyObjectId()
    integration_dict = integration_data.dict()
    integration_dict["_id"] = integration_id

    await db.projects.update_one(
        {"_id": project_id},
        {"$push": {"integrations": integration_dict}}
    )
    updated_project = await db.projects.find_one({"_id": project_id})
    return ProjectResponse(**updated_project)

@projects_router.get("/{project_id}/integrations", response_model=List[IntegrationResponse], summary="Retrieves a list of all integrations for a specific project.")
async def list_project_integrations(project: ProjectInDB = Depends(get_project_or_404)):
    return [IntegrationResponse(**integration) for integration in project.integrations]

@projects_router.get("/{project_id}/integrations/{integration_id}", response_model=IntegrationResponse, summary="Retrieves details of a specific integration within a project.")
async def get_project_integration(
    integration_id: PyObjectId,
    project: ProjectInDB = Depends(get_project_or_404)
):
    for integration in project.integrations:
        if integration.id == integration_id:
            return IntegrationResponse(**integration.dict())
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration not found")

@projects_router.put("/{project_id}/integrations/{integration_id}", response_model=IntegrationResponse, summary="Updates an existing integration within a project.")
async def update_project_integration(
    integration_id: PyObjectId,
    integration_update: IntegrationUpdate,
    project: ProjectInDB = Depends(get_project_or_404),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    update_data = integration_update.dict(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update")

    # MongoDB arrayFilters to update a specific embedded document
    result = await db.projects.update_one(
        {"_id": project.id, "integrations._id": integration_id},
        {"$set": {f"integrations.$.{k}": v for k, v in update_data.items()}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration not found or no changes made")

    updated_project = await db.projects.find_one({"_id": project.id})
    for integration in updated_project["integrations"]:
        if integration["_id"] == integration_id:
            return IntegrationResponse(**integration)
    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve updated integration")


@projects_router.delete("/{project_id}/integrations/{integration_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Removes an integration from a project.")
async def delete_project_integration(
    integration_id: PyObjectId,
    project: ProjectInDB = Depends(get_project_or_404),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    result = await db.projects.update_one(
        {"_id": project.id},
        {"$pull": {"integrations": {"_id": integration_id}}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integration not found or already removed")
    return


# --- Project Alert Configurations Routes ---
@projects_router.post("/{project_id}/alerts", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED, summary="Creates a new alert configuration for a specific project.")
async def add_alert_config_to_project(
    project_id: PyObjectId,
    alert_data: AlertConfigurationCreate,
    project: ProjectInDB = Depends(get_project_or_404),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    alert_id = PyObjectId()
    alert_dict = alert_data.dict()
    alert_dict["_id"] = alert_id

    await db.projects.update_one(
        {"_id": project_id},
        {"$push": {"alert_configurations": alert_dict}}
    )
    updated_project = await db.projects.find_one({"_id": project_id})
    return ProjectResponse(**updated_project)

@projects_router.get("/{project_id}/alerts", response_model=List[AlertConfigurationResponse], summary="Retrieves a list of all alert configurations for a specific project.")
async def list_project_alerts(project: ProjectInDB = Depends(get_project_or_404)):
    return [AlertConfigurationResponse(**alert) for alert in project.alert_configurations]

@projects_router.get("/{project_id}/alerts/{alert_id}", response_model=AlertConfigurationResponse, summary="Retrieves details of a specific alert configuration within a project.")
async def get_project_alert(
    alert_id: PyObjectId,
    project: ProjectInDB = Depends(get_project_or_404)
):
    for alert in project.alert_configurations:
        if alert.id == alert_id:
            return AlertConfigurationResponse(**alert.dict())
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert configuration not found")

@projects_router.put("/{project_id}/alerts/{alert_id}", response_model=AlertConfigurationResponse, summary="Updates an existing alert configuration within a project.")
async def update_project_alert(
    alert_id: PyObjectId,
    alert_update: AlertConfigurationUpdate,
    project: ProjectInDB = Depends(get_project_or_404),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    update_data = alert_update.dict(exclude_unset=True)
    if not update_data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No fields to update")

    result = await db.projects.update_one(
        {"_id": project.id, "alert_configurations._id": alert_id},
        {"$set": {f"alert_configurations.$.{k}": v for k, v in update_data.items()}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert configuration not found or no changes made")

    updated_project = await db.projects.find_one({"_id": project.id})
    for alert in updated_project["alert_configurations"]:
        if alert["_id"] == alert_id:
            return AlertConfigurationResponse(**alert)
    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve updated alert configuration")

@projects_router.delete("/{project_id}/alerts/{alert_id}", status_code=status.HTTP_204_NO_CONTENT, summary="Deletes an alert configuration from a project.")
async def delete_project_alert(
    alert_id: PyObjectId,
    project: ProjectInDB = Depends(get_project_or_404),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    result = await db.projects.update_one(
        {"_id": project.id},
        {"$pull": {"alert_configurations": {"_id": alert_id}}}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert configuration not found or already removed")
    return


# --- Metric Routes ---
@metrics_router.post("/", response_model=MetricResponse, status_code=status.HTTP_201_CREATED, summary="Ingests a single metric data point.")
async def ingest_single_metric(
    metric_data: MetricCreate,
    current_user: UserInDB = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    # Verify project ownership
    project = await db.projects.find_one({"_id": metric_data.project_id, "user_id": current_user.id})
    if not project:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Project not found or you don't own it")

    metric_in_db = MetricInDB(**metric_data.dict())
    new_metric = await db.metrics.insert_one(metric_in_db.dict(by_alias=True, exclude={"id"}))
    created_metric = await db.metrics.find_one({"_id": new_metric.inserted_id})
    return MetricResponse(**created_metric)

@metrics_router.post("/batch", response_model=List[MetricResponse], status_code=status.HTTP_201_CREATED, summary="Ingests multiple metric data points in a single request.")
async def ingest_batch_metrics(
    batch_data: MetricCreateBatch,
    current_user: UserInDB = Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    if not batch_data.metrics:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No metrics provided in batch")

    # Verify ownership for all projects in the batch
    project_ids = {metric.project_id for metric in batch_data.metrics}
    owned_projects_cursor = db.projects.find({"_id": {"$in": list(project_ids)}, "user_id": current_user.id})
    owned_project_ids = {p["_id"] for p in await owned_projects_cursor.to_list(length=len(project_ids))}

    metrics_to_insert = []
    for metric_data in batch_data.metrics:
        if metric_data.project_id not in owned_project_ids:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Project {metric_data.project_id} not found or you don't own it. Aborting batch."
            )
        metrics_to_insert.append(MetricInDB(**metric_data.dict()).dict(by_alias=True, exclude={"id"}))

    if metrics_to_insert:
        result = await db.metrics.insert_many(metrics_to_insert)
        inserted_metrics_cursor = db.metrics.find({"_id": {"$in": result.inserted_ids}})
        inserted_metrics = await inserted_metrics_cursor.to_list(length=len(result.inserted_ids))
        return [MetricResponse(**metric) for metric in inserted_metrics]
    return []


@projects_router.get("/{project_id}/metrics", response_model=List[MetricResponse], summary="Queries historical metric data points for a project, with filtering and pagination options.")
async def query_project_metrics(
    project_id: PyObjectId,
    query_params: MetricQuery = Depends(),
    project: ProjectInDB = Depends(get_project_or_404),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    filter_query = {"project_id": project_id}
    if query_params.metric_type:
        filter_query["metric_type"] = query_params.metric_type
    if query_params.start_date or query_params.end_date:
        filter_query["timestamp"] = {}
        if query_params.start_date:
            filter_query["timestamp"]["$gte"] = query_params.start_date
        if query_params.end_date:
            filter_query["timestamp"]["$lte"] = query_params.end_date

    metrics_cursor = db.metrics.find(filter_query).sort("timestamp", 1).skip(query_params.skip).limit(query_params.limit)
    metrics = await metrics_cursor.to_list(length=query_params.limit)
    return [MetricResponse(**metric) for metric in metrics]

@projects_router.get("/{project_id}/metrics/trends", response_model=List[MetricTrendResponse], summary="Retrieves aggregated daily/monthly metric trends for a project.")
async def get_project_metric_trends(
    project_id: PyObjectId,
    trend_query: MetricTrendQuery = Depends(),
    project: ProjectInDB = Depends(get_project_or_404),
    db: AsyncIOMotorDatabase = Depends(get_database)
):
    match_stage = {"project_id": project_id}
    if trend_query.metric_type:
        match_stage["metric_type"] = trend_query.metric_type
    if trend_query.start_date or trend_query.end_date:
        match_stage["timestamp"] = {}
        if trend_query.start_date:
            match_stage["timestamp"]["$gte"] = trend_query.start_date
        if trend_query.end_date:
            match_stage["timestamp"]["$lte"] = trend_query.end_date

    date_format = "%Y-%m-%d" if trend_query.interval == "day" else "%Y-%m"

    pipeline = [
        {"$match": match_stage},
        {"$group": {
            "_id": {
                "date": {"$dateToString": {"format": date_format, "date": "$timestamp"}}
            },
            "average_value": {"$avg": "$value"},
            "sum_value": {"$sum": "$value"},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id.date": 1}},
        {"$project": {
            "_id": 0,
            "date": "$_id.date",
            "average_value": "$average_value",
            "sum_value": "$sum_value",
            "count": "$count"
        }}
    ]

    trends_cursor = db.metrics.aggregate(pipeline)
    trends = await trends_cursor.to_list(length=None) # Get all results
    return [MetricTrendResponse(**trend) for trend in trends]


# --- Webhook Ingestion Route ---
@webhooks_router.post("/ingest/{project_id}/{integration_type}", status_code=status.HTTP_202_ACCEPTED, summary="Receives and processes incoming webhooks from external services.")
async def ingest_webhook(
    project_id: PyObjectId,
    integration_type: str,
    payload: WebhookPayload,
    api_key: str = Depends(verify_webhook_api_key),
    db: AsyncIOMotorDatabase = Depends(get_database),
    background_tasks: BackgroundTasks = None
):
    # In a real application, this would involve:
    # 1. Verifying the project_id exists and has an active integration of `integration_type`.
    # 2. Potentially verifying a webhook signature (e.g., X-Stripe-Signature) using the stored encrypted API key/secret.
    # 3. Parsing the `payload` based on `integration_type` to extract relevant metric data.
    # 4. Creating `MetricCreate` objects and inserting them into the 'metrics' collection.

    # For this example, we'll just log and acknowledge.
    # A real implementation would likely use a background task or a message queue
    # to process webhooks asynchronously to avoid blocking the response.

    project = await db.projects.find_one({"_id": project_id})
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    # Check if the project has an active integration of the specified type
    has_integration = False
    for integration in project.get("integrations", []):
        if integration.get("type") == integration_type and integration.get("is_active"):
            has_integration = True
            break
    if not has_integration:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Project does not have an active '{integration_type}' integration.")

    print(f"Received webhook for Project ID: {project_id}, Integration Type: {integration_type}")
    print(f"Webhook Payload: {payload.dict()}")

    # Example: Placeholder for actual metric extraction and insertion
    # This part would be highly specific to each integration type
    async def process_webhook_in_background(proj_id: PyObjectId, int_type: str, webhook_payload: WebhookPayload):
        print(f"Background task: Processing webhook for project {proj_id}, type {int_type}")
        # Example: Extract a 'value' and 'metric_type' from the payload
        # This is highly simplified. Real logic would be complex.
        try:
            if int_type == "Stripe" and webhook_payload.event_type == "invoice.payment_succeeded":
                mrr_value = webhook_payload.data.get("lines", {}).get("data", [{}])[0].get("amount_subtotal") / 100 # Example
                if mrr_value is not None:
                    metric_data = MetricCreate(
                        project_id=proj_id,
                        metric_type="MRR",
                        value=float(mrr_value),
                        timestamp=datetime.utcnow(),
                        source="Stripe"
                    )
                    metric_in_db = MetricInDB(**metric_data.dict())
                    await db.metrics.insert_one(metric_in_db.dict(by_alias=True, exclude={"id"}))
                    print(f"Inserted Stripe MRR metric: {mrr_value}")
            # Add more integration_type specific logic here
            else:
                print(f"No specific processing logic for {int_type} event {webhook_payload.event_type}")
        except Exception as e:
            print(f"Error processing webhook for project {proj_id}, type {int_type}: {e}")

    background_tasks.add_task(process_webhook_in_background, project_id, integration_type, payload)

    return {"message": "Webhook received and processing initiated.", "project_id": str(project_id), "integration_type": integration_type}


# --- Register Routers with the main app ---
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(projects_router)
app.include_router(metrics_router)
app.include_router(webhooks_router)
