import os
import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException, Depends, status
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
from passlib.context import CryptContext
from jose import jwt, JWTError

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///ads.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("Переменная окружения SECRET_KEY не задана")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 2880

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    login = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    group = Column(String, default="user")


class Advertisement(Base):
    __tablename__ = "advertisements"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    price = Column(Float, nullable=False)
    author = Column(String, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


class Ad(BaseModel):
    title: str
    description: str
    price: float


class AdUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None


class UserIn(BaseModel):
    login: str
    password: str
    group: str = "user"


class LoginIn(BaseModel):
    login: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


def get_current_user(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ")[1]
    payload = decode_access_token(token)
    if payload is None:
        return None
    user_id = payload.get("sub")
    if not user_id:
        return None
    return db.query(User).filter(User.id == user_id).first()


def require_auth(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Не авторизован")
    return user


def require_admin(user: User = Depends(require_auth)):
    if user.group != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Требуется роль admin")
    return user


app = FastAPI()


@app.post("/login", response_model=Token)
def login(data: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.login == data.login).first()
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный логин или пароль"
        )
    access_token = create_access_token(
        data={"sub": str(user.id)},
        expires_delta=timedelta(hours=48)
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/user", response_model=Dict[str, Any])
def create_user(data: UserIn, db: Session = Depends(get_db)):
    if data.group == "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Нельзя создавать пользователей с ролью admin")

    if db.query(User).filter(User.login == data.login).first():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Логин уже занят")

    new_user = User(
        login=data.login,
        password_hash=hash_password(data.password),
        group=data.group
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"id": new_user.id, "login": new_user.login, "group": new_user.group}


@app.get("/user", response_model=List[Dict[str, Any]])
def get_all_users(current_user: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.query(User).all()
    return [{"id": u.id, "login": u.login, "group": u.group} for u in users]


@app.get("/user/{user_id}", response_model=Dict[str, Any])
def get_user(user_id: int, current_user: Optional[User] = Depends(get_current_user), db: Session = Depends(get_db)):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Пользователь не найден")

    if current_user is None:
        return {"id": target.id, "login": target.login, "group": target.group}

    if current_user.group != "admin" and current_user.id != target.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Нет прав")

    return {"id": target.id, "login": target.login, "group": target.group}


@app.patch("/user/{user_id}", response_model=Dict[str, Any])
def patch_user(
    user_id: int,
    data: Dict[str, Any],
    current_user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Пользователь не найден")

    if current_user.group != "admin" and current_user.id != target.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Нет прав")

    if "group" in data and current_user.group != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Нельзя менять роль без прав admin")

    for key, value in data.items():
        if key in ["login", "password", "group"]:
            if key == "password":
                setattr(target, "password_hash", hash_password(value))
            else:
                setattr(target, key, value)

    db.commit()
    db.refresh(target)
    return {"id": target.id, "login": target.login, "group": target.group}


@app.delete("/user/{user_id}", response_model=Dict[str, Any])
def delete_user(
    user_id: int,
    current_user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Пользователь не найден")

    if current_user.group != "admin" and current_user.id != target.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Нет прав")

    db.delete(target)
    db.commit()
    return {"status": "ok", "message": "Пользователь удалён"}


@app.post("/advertisement", response_model=Dict[str, Any])
def create_advertisement(
    ad: Ad,
    current_user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    new_ad = Advertisement(
        title=ad.title,
        description=ad.description,
        price=ad.price,
        author=current_user.login,
        owner_id=current_user.id,
        created_at=datetime.utcnow()
    )
    db.add(new_ad)
    db.commit()
    db.refresh(new_ad)
    return {
        "id": new_ad.id,
        "title": new_ad.title,
        "description": new_ad.description,
        "price": new_ad.price,
        "author": new_ad.author,
        "owner_id": new_ad.owner_id,
        "created_at": new_ad.created_at.isoformat()
    }


@app.get("/advertisement/{ad_id}", response_model=Dict[str, Any])
def get_advertisement(ad_id: int, db: Session = Depends(get_db)):
    ad = db.query(Advertisement).filter(Advertisement.id == ad_id).first()
    if not ad:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Объявление не найдено")
    return {
        "id": ad.id,
        "title": ad.title,
        "description": ad.description,
        "price": ad.price,
        "author": ad.author,
        "owner_id": ad.owner_id,
        "created_at": ad.created_at.isoformat()
    }


@app.patch("/advertisement/{ad_id}", response_model=Dict[str, Any])
def patch_advertisement(
    ad_id: int,
    data: AdUpdate,
    current_user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    ad = db.query(Advertisement).filter(Advertisement.id == ad_id).first()
    if not ad:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Объявление не найдено")

    if current_user.group != "admin" and ad.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Это не ваше объявление")

    updates = data.model_dump(exclude_unset=True)
    for key, value in updates.items():
        setattr(ad, key, value)

    db.commit()
    db.refresh(ad)
    return {
        "id": ad.id,
        "title": ad.title,
        "description": ad.description,
        "price": ad.price,
        "author": ad.author,
        "owner_id": ad.owner_id,
        "created_at": ad.created_at.isoformat()
    }


@app.delete("/advertisement/{ad_id}", response_model=Dict[str, Any])
def delete_advertisement(
    ad_id: int,
    current_user: User = Depends(require_auth),
    db: Session = Depends(get_db)
):
    ad = db.query(Advertisement).filter(Advertisement.id == ad_id).first()
    if not ad:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Объявление не найдено")

    if current_user.group != "admin" and ad.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Это не ваше объявление")

    db.delete(ad)
    db.commit()
    return {"status": "ok", "message": "Объявление удалено"}


@app.get("/advertisement", response_model=Dict[str, Any])
def search_advertisement(
    limit: int = 50,
    offset: int = 0,
    title: Optional[str] = None,
    description: Optional[str] = None,
    min_price: Optional[float] = None,
    max_price: Optional[float] = None,
    author: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Advertisement)

    if title is not None:
        query = query.filter(Advertisement.title.ilike(f"%{title}%"))
    if description is not None:
        query = query.filter(Advertisement.description.ilike(f"%{description}%"))
    if min_price is not None:
        query = query.filter(Advertisement.price >= min_price)
    if max_price is not None:
        query = query.filter(Advertisement.price <= max_price)
    if author is not None:
        query = query.filter(Advertisement.author.ilike(f"%{author}%"))

    total = query.count()
    ads = query.offset(offset).limit(limit).all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "id": a.id,
                "title": a.title,
                "description": a.description,
                "price": a.price,
                "author": a.author,
                "owner_id": a.owner_id,
                "created_at": a.created_at.isoformat()
            }
            for a in ads
        ]
    }



if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=8000)