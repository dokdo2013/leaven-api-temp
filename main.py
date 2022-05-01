import time
from fastapi import FastAPI, HTTPException, status, Header, Request
from starlette.responses import JSONResponse
from typing import Optional
from sqlalchemy import create_engine
from pydantic import BaseModel
from datetime import datetime, timedelta
import requests
import json
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import bcrypt
import jwt
import dotenv
import os


dotenv.load_dotenv()
dbinfo = os.getenv('SQLADDR')
db = create_engine(dbinfo)
db.execute("SET time_zone='Asia/Seoul'")

description = """
### 레븐 API
Nest.js API 구축 전 급한대로 만드는 Fastapi API

### 응답
- 기본적인 응답 컨벤션은 HTTP 표준 응답 코드를 따름 (200, 400, 503 등)
- 상세한 응답 내용은 반환되는 code와 message로 기술
"""

# CORS Allow Origin Predefined addresses
origins = [
    "https://*.leaven.team",
    "https://onair.leaven.team",
    "https://multi.leaven.team",
    "https://dev-multi.leaven.team",
    "https://*.leaven.kr",
    "http://localhost:5500",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://127.0.0.1:5500",
    "http://127.0.0.1:5501",
    "http://172.30.1.2:3000",
]

app = FastAPI(
    title="LEAVEN API v1",
    description=description,
    version="v1",
    swagger_ui_parameters={"docExpansion": 'none'}
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class CommonResponse(BaseModel):
    code: str = 'SUCCESS'
    message: str
    message_ko: str
    data: list


def sqlAlchemyRowToDict(results):
    return [dict(r) for r in results]


def commonResponse(status_code=200, code='SUCCESS', message='성공', data={}, cookies=[], headers={}):
    res = {
        "code": code,
        "message": message,
        "data": data
    }
    response = JSONResponse(res, status_code=status_code, headers=headers)
    for cookie in cookies:
        response.set_cookie(cookie['key'], cookie['value'], secure=cookie['secure'], httponly=cookie['httponly'])
    return response


@app.get("/broadcast", status_code=200, tags=["방송정보"], summary="레븐 기본 방송정보")
async def getBroadcast():
    sql = "SELECT idx, streamer_name, streamer_name_ko, broadcast_status, on_broadcast_datetime, off_broadcast_datetime, update_datetime FROM leaven"
    res = db.execute(sql)
    data = res.fetchall()
    broad_list = sqlAlchemyRowToDict(data)

    result = {
        "code": "SUCCESS",
        "data": broad_list
    }
    return result


@app.get("/broadcast/history", status_code=200, tags=["방송정보"], summary="레븐 전체 방송 History")
async def getBroadcast(start_date: str, end_date: str):
    start_date = f"{start_date} 00:00:00"
    end_date = f"{end_date} 23:59:59"

    sql = f"SELECT lh.idx, lh.reg_datetime, l.streamer_name, l.streamer_name_ko, action_type \
        FROM leaven_history lh \
        JOIN leaven l on lh.leaven_idx = l.idx \
        WHERE lh.reg_datetime >= '{start_date}' and lh.reg_datetime <= '{end_date}' \
        ORDER BY lh.idx asc"

    res = db.execute(sql)
    data = res.fetchall()
    broad_list = sqlAlchemyRowToDict(data)

    result = {
        "code": "SUCCESS",
        "data": broad_list
    }
    return result


if __name__ == '__main__':
    uvicorn.run("main:app", host="0.0.0.0", port=9090, reload=True)
    # getInfo()