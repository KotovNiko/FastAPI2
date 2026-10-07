from fastapi import FastAPI, Request
from pydantic import BaseModel
from datetime import datetime
from typing import Optional
import uvicorn

app = FastAPI()

advertisements = []
id_counter = 1


class Ad(BaseModel):
    title: str
    description: str
    price: float
    author: str


class AdUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    author: Optional[str] = None


@app.post("/advertisement")
def create_advertisement(ad: Ad):
    global id_counter
    data = ad.model_dump()
    data["id"] = id_counter
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
def patch_advertisement(ad_id: int, data: AdUpdate):
    updates = data.model_dump(exclude_unset=True)
    if not updates:
        return {"error": "нет полей для обновления"}
    for ad in advertisements:
        if ad["id"] == ad_id:
            ad.update(updates)
            print("обновили", ad_id)
            return ad
    return {"error": "нет такого объявления("}


@app.delete("/advertisement/{ad_id}")
def delete_advertisement(ad_id: int):
    global advertisements
    for ad in advertisements:
        if ad["id"] == ad_id:
            advertisements.remove(ad)
            return {"status": "ok", "message": "удалили"}
    return {"error": "нет такого объявления("}


@app.get("/advertisement")
def search_advertisement(request: Request):
    params = dict(request.query_params)
    if not params:
        return advertisements

    allowed_fields = {"title", "description", "price", "author", "id", "created_at"}

    result = []
    for ad in advertisements:
        match = True
        for field, value in params.items():
            if field not in allowed_fields:
                match = False
                break
            ad_value = ad.get(field)
            if field == "price":
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
