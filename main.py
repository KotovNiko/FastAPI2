from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional
import uvicorn
import uuid

app = FastAPI()

advertisements = []
id_counter = 1


class Ad(BaseModel):
    title: str
    description: str
    price: float


class AdUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None


users = []
user_id_counter = 1


tokens = {}


class UserIn(BaseModel):
    login: str
    password: str
    group: str = "user"


class LoginIn(BaseModel):
    login: str
    password: str


def get_current_user(request: Request):
    token = request.headers.get("token")
    if not token:
        return None
    info = tokens.get(token)
    if info is None:
        return None
    if datetime.now() > info["expires"]:
        del tokens[token]
        return None
    for user in users:
        if user["id"] == info["user_id"]:
            return user
    return None


@app.post("/login")
def login(data: LoginIn):
    for user in users:
        if user["login"] == data.login and user["password"] == data.password:
            token = uuid.uuid4().hex
            tokens[token] = {
                "user_id": user["id"],
                "expires": datetime.now() + timedelta(hours=48),
            }
            print("залогинился", user["login"], "токен", token)
            return {"token": token}
    raise HTTPException(status_code=401, detail="неверный логин или пароль")


@app.post("/user")
def create_user(data: UserIn):
    global user_id_counter
    user = data.model_dump()
    user["id"] = user_id_counter
    user_id_counter += 1
    users.append(user)
    print("создали юзера", user)
    return user


@app.get("/user")
def get_all_users(request: Request):
    current_user = get_current_user(request)
    if current_user is None:
        raise HTTPException(status_code=403, detail="нет прав")
    return users


@app.get("/user/{user_id}")
def get_user(user_id: int):
    for user in users:
        if user["id"] == user_id:
            return user
    return {"error": "нет такого юзера("}


@app.patch("/user/{user_id}")
def patch_user(user_id: int, data: dict, request: Request):
    current_user = get_current_user(request)
    if current_user is None:
        raise HTTPException(status_code=403, detail="нет прав")

    for user in users:
        if user["id"] == user_id:
            if current_user["group"] != "admin" and current_user["id"] != user_id:
                raise HTTPException(status_code=403, detail="нет прав")
            for key in data:
                user[key] = data[key]
            return user
    return {"error": "нет такого юзера("}


@app.delete("/user/{user_id}")
def delete_user(user_id: int, request: Request):
    current_user = get_current_user(request)
    if current_user is None:
        raise HTTPException(status_code=403, detail="нет прав")

    for user in users:
        if user["id"] == user_id:
            if current_user["group"] != "admin" and current_user["id"] != user_id:
                raise HTTPException(status_code=403, detail="нет прав")
            users.remove(user)
            return {"status": "ok", "message": "удалили"}
    return {"error": "нет такого юзера("}


@app.post("/advertisement")
def create_advertisement(ad: Ad, request: Request):
    global id_counter
    current_user = get_current_user(request)
    if current_user is None:
        raise HTTPException(status_code=403, detail="нет прав, залогинься")

    data = ad.model_dump()
    data["id"] = id_counter
    data["author"] = current_user["login"]
    data["owner_id"] = current_user["id"]
    data["created_at"] = datetime.now().isoformat()
    id_counter += 1
    advertisements.append(data)
    print("создали объявление -> ", data)
    return data


@app.get("/advertisement/{ad_id}")
def get_advertisement(ad_id: int):
    for ad in advertisements:
        if ad["id"] == ad_id:
            return ad
    return {"error": "нет такого объявления("}


@app.patch("/advertisement/{ad_id}")
def patch_advertisement(ad_id: int, data: AdUpdate, request: Request):
    current_user = get_current_user(request)
    if current_user is None:
        raise HTTPException(status_code=403, detail="нет прав, залогинься")

    updates = data.model_dump(exclude_unset=True)  # только переданные поля
    for ad in advertisements:
        if ad["id"] == ad_id:
            if current_user["group"] != "admin" and ad["owner_id"] != current_user["id"]:
                raise HTTPException(status_code=403, detail="это не твое объявление")
            ad.update(updates)
            print("обновили", ad_id)
            return ad
    return {"error": "нет такого объявления("}


@app.delete("/advertisement/{ad_id}")
def delete_advertisement(ad_id: int, request: Request):
    current_user = get_current_user(request)
    if current_user is None:
        raise HTTPException(status_code=403, detail="нет прав, залогинься")

    global advertisements
    for ad in advertisements:
        if ad["id"] == ad_id:
            if current_user["group"] != "admin" and ad["owner_id"] != current_user["id"]:
                raise HTTPException(status_code=403, detail="это не твое объявление")
            advertisements.remove(ad)
            return {"status": "ok", "message": "удалили"}
    return {"error": "нет такого объявления("}


@app.get("/advertisement")
def search_advertisement(request: Request):
    params = dict(request.query_params)
    if not params:
        return advertisements

    allowed_fields = {"title", "description", "price", "author", "id", "created_at"}
    numeric_fields = {"price", "id"}

    result = []
    for ad in advertisements:
        match = True
        for field, value in params.items():
            if field not in allowed_fields:
                match = False
                break
            ad_value = ad.get(field)
            if field in numeric_fields:
                try:
                    if float(ad_value) != float(value):
                        match = False
                        break
                except (TypeError, ValueError):
                    match = False
                    break
            else:
                if str(ad_value) != str(value):
                    match = False
                    break
        if match:
            result.append(ad)
    return result


if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=8000)