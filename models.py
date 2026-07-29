from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from bson import ObjectId

class PyObjectId(str):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate
    @classmethod
    def validate(cls, v):
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid objectid")
        return str(v)

class UserCreate(BaseModel):
    name: str = ""
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: Optional[str] = None
    name: str = ""
    email: str

class UserInDB(BaseModel):
    id: Optional[str] = None
    name: str = ""
    email: str
    password_hash: str

class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None

class ProjectCreate(BaseModel):
    name: str

class ProjectResponse(BaseModel):
    id: Optional[str] = None
    name: str

class ProjectInDB(BaseModel):
    id: Optional[str] = None
    name: str
    user_id: str

class ProjectUpdate(BaseModel):
    name: Optional[str] = None

class IntegrationCreate(BaseModel):
    type: str

class IntegrationUpdate(BaseModel):
    type: Optional[str] = None

class IntegrationResponse(BaseModel):
    id: Optional[str] = None
    type: str

class AlertConfigurationCreate(BaseModel):
    name: str

class AlertConfigurationUpdate(BaseModel):
    name: Optional[str] = None

class AlertConfigurationResponse(BaseModel):
    id: Optional[str] = None
    name: str

class MetricCreate(BaseModel):
    metric_type: str
    value: float

class MetricCreateBatch(BaseModel):
    metrics: List[MetricCreate]

class MetricResponse(BaseModel):
    id: Optional[str] = None
    metric_type: str
    value: float

class MetricQuery(BaseModel):
    metric_type: Optional[str] = None

class MetricTrendQuery(BaseModel):
    metric_type: str

class MetricTrendResponse(BaseModel):
    metric_type: str
    trend: List[float] = []

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    user_id: Optional[str] = None

class WebhookPayload(BaseModel):
    event: str
    data: dict = {}
