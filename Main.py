from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt
import databases
import sqlalchemy

app = FastAPI()

# Configure and connect to your database (PostgreSQL in this example)
DATABASE_URL = "postgresql://user:password@localhost/blog_db"
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

# Define User table
users = sqlalchemy.Table(
    "users",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("email", sqlalchemy.String, unique=True, index=True),
    sqlalchemy.Column("password", sqlalchemy.String),
)

# Define Blog Post table
blog_posts = sqlalchemy.Table(
    "blog_posts",
    metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("title", sqlalchemy.String),
    sqlalchemy.Column("content", sqlalchemy.Text),
    sqlalchemy.Column("author_id", sqlalchemy.Integer, sqlalchemy.ForeignKey("users.id")),
)

# Create tables if they don't exist
engine = sqlalchemy.create_engine(DATABASE_URL)
metadata.create_all(engine)

# Security and Token
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Token creation function
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# User registration model
class UserCreate(BaseModel):
    email: str
    password: str

# User registration API with email validation and duplicate email check
@app.post("/register", response_model=UserCreate)
async def register(user: UserCreate):
    query = users.insert().values(email=user.email, password=pwd_context.hash(user.password))
    user_id = await database.execute(query)
    if user_id:
        return user
    raise HTTPException(status_code=400, detail="User registration failed")

# JWT token creation and validation
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# User Login model
class UserLogin(BaseModel):
    email: str
    password: str

# User login API with JWT authentication
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await database.fetch_one(users.select().where(users.c.email == form_data.username))
    if user and pwd_context.verify(form_data.password, user["password"]):
        access_token_expires = timedelta(minutes=30)
        access_token = create_access_token(data={"sub": form_data.username}, expires_delta=access_token_expires)
        return {"access_token": access_token, "token_type": "bearer"}
    raise HTTPException(status_code=400, detail="Login failed")

# Blog Post model
class BlogPost(BaseModel):
    title: str
    content: str

# Create a new blog post API
@app.post("/create-post", response_model=BlogPost)
async def create_post(post: BlogPost, current_user: str = Depends(oauth2_scheme)):
    query = users.select().where(users.c.email == current_user)
    user = await database.fetch_one(query)
    if user:
        query = blog_posts.insert().values(title=post.title, content=post.content, author_id=user["id"])
        post_id = await database.execute(query)
        if post_id:
            return post
    raise HTTPException(status_code=400, detail="Blog post creation failed")

# Comment model
class Comment(BaseModel):
    content: str

# Post a comment on a blog post API
@app.post("/post-comment/{post_id}", response_model=Comment)
async def post_comment(post_id: int, comment: Comment, current_user: str = Depends(oauth2_scheme)):
    query = blog_posts.select().where(blog_posts.c.id == post_id)
    post = await database.fetch_one(query)
    if post:
        query = users.select().where(users.c.email == current_user)
        user = await database.fetch_one(query)
        if user:
            query = comment.insert().values(content=comment.content, post_id=post_id, author_id=user["id"])
            comment_id = await database.execute(query)
            if comment_id:
                return comment
    raise HTTPException(status_code=400, detail="Comment posting failed")

if __name__ == "_main_":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)