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
import sentry_sdk
from sentry_sdk.integrations.asgi import SentryAsgiMiddleware


dotenv.load_dotenv()
dbinfo = os.getenv('SQLADDR')
dbinfo2 = os.getenv('SQLADDR2')
jwtSalt = os.getenv('JWT_SALT')
db = create_engine(dbinfo)
db.execute("SET time_zone='Asia/Seoul'")
db2 = create_engine(dbinfo2)
db2.execute("SET time_zone='Asia/Seoul'")

sentry_sdk.init(dsn=os.getenv('DSN'))

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
    "https://rust.leaven.team",
    "https://gell.leaven.team",
    "https://gg.leaven.team",
    "https://junharry.vercel.app",
    "https://junharry.com",
    "https://www.junharry.com",
    "https://junharry-git-develop-haenu.vercel.app",
    "https://*.leaven.kr",
    "http://localhost:5500",
    "http://localhost:3000",
    "http://localhost:3001",
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

app.add_middleware(SentryAsgiMiddleware)


class CommonResponse(BaseModel):
    code: str = 'SUCCESS'
    message: str
    message_ko: str
    data: list


class gellData(BaseModel):
    name: str
    count: int
    csrf_token: str


class gellName(BaseModel):
    name: str
    count: int
    password: str


class gellMerge(BaseModel):
    target_name: str
    name: str
    password: str


class gellToken(BaseModel):
    name: str
    password: str


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


async def common_token_validation(token):
    try:
        payload = jwt.decode(token, jwtSalt, algorithms='HS256')
    except jwt.exceptions.InvalidSignatureError:
        return [401, 'INVALID_TOKEN', '로그인 정보가 유효하지 않습니다. 다시 로그인해주세요']
    else:
        if int(payload['expire']) >= int(str(time.time()).split('.')[0]):  # 토큰 인증 성공
            return [200, 'SUCCESS', '성공']
        else:  # 토큰 만료
            return [401, 'TOKEN_EXPIRED', '로그인 정보가 만료되었습니다. 다시 로그인해주세요']


@app.get("/live", status_code=200, tags=["방송정보"], summary="레븐 라이브 정보")
async def live():
    sql = "SELECT streamer_name FROM leaven WHERE broadcast_status = 'ON'"
    info = db.execute(sql)
    data = info.fetchall()
    streaming_list = sqlAlchemyRowToDict(data)
    streamer_list = []
    for streamer in streaming_list:
        streamer_list.append(streamer['streamer_name'])
    return commonResponse(data=streamer_list)


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
async def getBroadcast(start_date: str, end_date: str, streamer: str):
    start_date = f"{start_date} 00:00:00"
    end_date = f"{end_date} 23:59:59"
    if streamer == 'all':
        sql = f"SELECT lh.idx, lh.reg_datetime, l.streamer_name, l.streamer_name_ko, action_type \
            FROM leaven_history lh \
            JOIN leaven l on lh.leaven_idx = l.idx \
            WHERE lh.reg_datetime >= '{start_date}' and lh.reg_datetime <= '{end_date}' \
            ORDER BY lh.idx asc"
    else:
        sql = f"SELECT lh.idx, lh.reg_datetime, l.streamer_name, l.streamer_name_ko, action_type \
            FROM leaven_history lh \
            JOIN leaven l on lh.leaven_idx = l.idx \
            WHERE lh.reg_datetime >= '{start_date}' and lh.reg_datetime <= '{end_date}' and l.streamer_name = '{streamer}' \
            ORDER BY lh.idx asc"

    res = db.execute(sql)
    data = res.fetchall()
    broad_list = sqlAlchemyRowToDict(data)

    result = {
        "code": "SUCCESS",
        "data": broad_list
    }
    return result


@app.get('/junharry/schedule', tags=["전해리 방송일정"], summary="전해리 방송일정 조회")
async def getJunharrySchedule():
    sql = "SELECT idx, DATE_FORMAT(date, '%%Y-%%m-%%d %%H:%%i:%%s') as date, name, is_rest, DATE_FORMAT(reg_datetime, '%%Y-%%m-%%d %%H:%%i:%%s') as reg_datetime FROM junharry_schedule WHERE del_stat = 0 ORDER BY date ASC"
    res = db2.execute(sql)
    data = res.fetchall()
    return commonResponse(200, data=sqlAlchemyRowToDict(data))


class harrySchedule(BaseModel):
    date: str
    name: str
    is_rest: int

@app.post('/junharry/schedule', tags=["전해리 방송일정"], summary="전해리 방송일정 등록")
async def postJunharrySchedule(schedule: harrySchedule, X_Access_Token: str = Header(None)):
    if X_Access_Token is None or X_Access_Token == 'null':
        return commonResponse(401, 'TOKEN_NOT_PROVIDED', '로그인 정보가 없습니다. 다시 로그인해주세요')
    validation_result = await common_token_validation(X_Access_Token)
    if validation_result[0] != 200:
        return commonResponse(validation_result[0], validation_result[1], validation_result[2])

    if schedule.date == '' or schedule.name == '':
        return commonResponse(400, message="입력값이 잘못되었습니다.")
    if schedule.is_rest != 0 and schedule.is_rest != 1:
        return commonResponse(400, message="입력값이 잘못되었습니다.")

    # 중복등록 제한
    check_sql = f"SELECT count(*) as cnt FROM junharry_schedule WHERE date = '{schedule.date}' and del_stat = 0"
    check_res = db2.execute(check_sql)
    if check_res.fetchone()[0] != 0:
        return commonResponse(400, message="이미 등록된 일시입니다.")

    schedule.name = schedule.name.replace("'", "\"")
    sql = f"INSERT INTO junharry_schedule(date, name, is_rest) VALUES('{schedule.date}', '{schedule.name}', {schedule.is_rest})"
    db2.execute(sql)
    return commonResponse(201, message="방송일정 등록에 성공했습니다!")


@app.delete('/junharry/schedule/{idx}', tags=["전해리 방송일정"], summary="전해리 방송일정 삭제")
async def deleteJunharrySchedule(idx: int, X_Access_Token: str = Header(None)):
    if X_Access_Token is None or X_Access_Token == 'null':
        return commonResponse(401, 'TOKEN_NOT_PROVIDED', '로그인 정보가 없습니다. 다시 로그인해주세요')
    validation_result = await common_token_validation(X_Access_Token)
    if validation_result[0] != 200:
        return commonResponse(validation_result[0], validation_result[1], validation_result[2])

    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sql = f"UPDATE junharry_schedule SET del_stat = 1, del_datetime = '{date}' WHERE idx = {idx}"
    db2.execute(sql)
    return commonResponse(200)


@app.get('/junharry/notice', tags=["전해리 방송일정"], summary="전해리 공지사항")
async def getJunharryNotice():
    sql = "SELECT idx, title, content, DATE_FORMAT(reg_datetime, '%%Y-%%m-%%d %%H:%%i:%%s') as reg_datetime FROM junharry_notice WHERE del_stat = 0 ORDER BY reg_datetime DESC"
    res = db2.execute(sql)
    data = res.fetchall()
    return commonResponse(200, data=sqlAlchemyRowToDict(data))


class junharryNotice(BaseModel):
    title: str
    content: str


@app.post('/junharry/notice', tags=["전해리 방송일정"], summary="전해리 공지사항 등록")
async def postJunharryNotice(data: junharryNotice, X_Access_Token: str = Header(None)):
    if X_Access_Token is None or X_Access_Token == 'null':
        return commonResponse(401, 'TOKEN_NOT_PROVIDED', '로그인 정보가 없습니다. 다시 로그인해주세요')
    validation_result = await common_token_validation(X_Access_Token)
    if validation_result[0] != 200:
        return commonResponse(validation_result[0], validation_result[1], validation_result[2])

    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data.title = data.title.replace("'", "\"")
    data.content = data.content.replace("'", "\"")
    sql = f"INSERT INTO junharry_notice(title, content, reg_datetime) VALUES('{data.title}', '{data.content}', '{date}')"
    db2.execute(sql)
    return commonResponse(201, message="공지사항 등록에 성공했습니다.")


@app.delete('/junharry/notice/{idx}', tags=["전해리 방송일정"], summary="전해리 공지사항 삭제")
async def deleteJunharryNotice(idx: int, X_Access_Token: str = Header(None)):
    if X_Access_Token is None or X_Access_Token == 'null':
        return commonResponse(401, 'TOKEN_NOT_PROVIDED', '로그인 정보가 없습니다. 다시 로그인해주세요')
    validation_result = await common_token_validation(X_Access_Token)
    if validation_result[0] != 200:
        return commonResponse(validation_result[0], validation_result[1], validation_result[2])

    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sql = f"UPDATE junharry_notice SET del_stat = 1, del_datetime = '{date}' WHERE idx = {idx}"
    db2.execute(sql)
    return commonResponse(200, message="공지사항 삭제에 성공했습니다.")


@app.get('/junharry/youtube', tags=["전해리 방송일정"], summary="전해리 유튜브")
async def getJunharryYoutube(all: bool = False):
    if all is True:
        sql = "SELECT idx, link, cover_img, name, DATE_FORMAT(upload_date, '%%Y-%%m-%%d') as upload_date, DATE_FORMAT(reg_datetime, '%%Y-%%m-%%d %%H:%%i:%%s') as reg_datetime FROM junharry_youtube WHERE del_stat = 0 ORDER BY upload_date DESC"
    else:
        sql = "SELECT idx, link, cover_img, name, DATE_FORMAT(upload_date, '%%Y-%%m-%%d') as upload_date, DATE_FORMAT(reg_datetime, '%%Y-%%m-%%d %%H:%%i:%%s') as reg_datetime FROM junharry_youtube WHERE del_stat = 0 ORDER BY upload_date DESC LIMIT 3"
    res = db2.execute(sql)
    data = res.fetchall()
    return commonResponse(200, data=sqlAlchemyRowToDict(data))


class junharryYoutube(BaseModel):
    link: str
    cover_img: str
    name: str
    upload_date: str


@app.post('/junharry/youtube', tags=["전해리 방송일정"], summary="전해리 유튜브 등록")
async def postJunharryYoutube(data: junharryYoutube, X_Access_Token: str = Header(None)):
    if X_Access_Token is None or X_Access_Token == 'null':
        return commonResponse(401, 'TOKEN_NOT_PROVIDED', '로그인 정보가 없습니다. 다시 로그인해주세요')
    validation_result = await common_token_validation(X_Access_Token)
    if validation_result[0] != 200:
        return commonResponse(validation_result[0], validation_result[1], validation_result[2])

    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data.name = data.name.replace("'", "\"")

    sql = f"INSERT INTO junharry_youtube(link, cover_img, name, upload_date, reg_datetime) VALUES('{data.link}', '{data.cover_img}', '{data.name}', '{data.upload_date}', '{date}')"
    db2.execute(sql)
    return commonResponse(201, message="유튜브 등록에 성공했습니다.")


@app.delete('/junharry/youtube/{idx}', tags=["전해리 방송일정"], summary="전해리 유튜브 삭제")
async def deleteJunharryYoutube(idx: int, X_Access_Token: str = Header(None)):
    if X_Access_Token is None or X_Access_Token == 'null':
        return commonResponse(401, 'TOKEN_NOT_PROVIDED', '로그인 정보가 없습니다. 다시 로그인해주세요')
    validation_result = await common_token_validation(X_Access_Token)
    if validation_result[0] != 200:
        return commonResponse(validation_result[0], validation_result[1], validation_result[2])

    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sql = f"UPDATE junharry_youtube SET del_stat = 1, del_datetime = '{date}' WHERE idx = {idx}"
    db2.execute(sql)
    return commonResponse(200, message="유튜브 삭제에 성공했습니다.")


@app.get('/junharry/plain/{key}', tags=["전해리 방송일정"], summary="전해리 기타 데이터 조회")
async def getJunharryPlain(key: str):
    sql = f"SELECT `value` FROM junharry_text WHERE `key` = '{key}'"
    res = db2.execute(sql)
    data = res.fetchone()
    return commonResponse(200, data=data[0])


class junharryPlain(BaseModel):
    key: str
    value: str


@app.put('/junharry/plain', tags=["전해리 방송일정"], summary="전해리 기타 데이터 수정")
async def putJunharryPlain(data: junharryPlain, X_Access_Token: str = Header(None)):
    if X_Access_Token is None or X_Access_Token == 'null':
        return commonResponse(401, 'TOKEN_NOT_PROVIDED', '로그인 정보가 없습니다. 다시 로그인해주세요')
    validation_result = await common_token_validation(X_Access_Token)
    if validation_result[0] != 200:
        return commonResponse(validation_result[0], validation_result[1], validation_result[2])

    data.value = data.value.replace("'", "\"")
    sql = f"UPDATE junharry_text SET `value`='{data.value}' WHERE `key` = '{data.key}'"
    db2.execute(sql)
    return commonResponse(200, message="수정에 성공했습니다.")


class junharryToken(BaseModel):
    user_id: str
    user_pw: str


@app.post('/junharry/token', tags=["전해리 방송일정"], summary="전해리 토큰 발급")
async def postJunharryToken(loginData: junharryToken):
    sql = f"SELECT count(*) as cnt FROM junharry_account WHERE user_id = '{loginData.user_id}' and user_pw = '{loginData.user_pw}'"
    res = db2.execute(sql)
    data = res.fetchone()
    count = data[0]
    if count == 0:
        return commonResponse(401, 'Unauthorized', '아이디 또는 비밀번호가 잘못 입력되었습니다')
    else:
        jwtData = {
            "user_id": loginData.user_id,
            "expire": int((str(time.time())).split('.')[0]) + 1209600
        }
        token = jwt.encode(jwtData, jwtSalt)
    return commonResponse(200, data={"token": token})


@app.post('/gell', status_code=201, tags=["gellgell"], summary="gellgell 기록 등록")
async def postGell(gell: gellData):
    sql = f"SELECT idx, csrf_token, count FROM gell WHERE name = '{gell.name}'"
    res = db2.execute(sql)
    data = res.fetchone()
    if data is None:
        return commonResponse(404, 'DATA_EMPTY', '해당되는 이름이 없습니다.')
    idx = data[0]
    csrf_token = data[1]
    curr_count = data[2]
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if csrf_token != gell.csrf_token:
        return commonResponse(401, 'UNAUTHORIZED', 'CSRF 토큰이 일치하지 않습니다. 새로고침해주세요.')
    elif curr_count > gell.count:
        return commonResponse(400, 'OLD_DATA', '뭔가가 잘못됐어요!')
    else:
        sql1 = f"UPDATE gell SET count = {gell.count}, edit_datetime = '{now}' WHERE name = '{gell.name}'"
        sql2 = f"INSERT INTO gell_log(gell_idx, gell_count) VALUES({idx}, {gell.count})"
        db2.execute(sql1)
        db2.execute(sql2)
        return commonResponse(201)


@app.delete('/gell', status_code=200, tags=["gellgell"], summary="gellgell 계정 지우기")
async def deleteGell(gell: gellToken):
    sql1 = f"SELECT count(*) as cnt FROM gell WHERE name = '{gell.name}' and password = '{gell.password}'"
    res = db2.execute(sql1)
    count = res.fetchone()[0]

    if count > 0:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sql4 = f"UPDATE gell SET del_stat = 1, del_datetime = '{now}' WHERE name = '{gell.name}'"
        db2.execute(sql4)
        return commonResponse(200)
    else:
        return commonResponse(404, 'DATA_EMPTY', '아이디/비밀번호를 다시 확인해주세요.')


@app.post('/gell/name', status_code=201, tags=["gellgell"], summary="gellgell 이름 설정")
async def postGellName(gell: gellName):
    sql1 = f"SELECT count(*) as cnt FROM gell WHERE name = '{gell.name}'"
    res = db2.execute(sql1)
    count = res.fetchone()[0]

    if count > 0:
        return commonResponse(400, 'ALREADY_EXIST', '이미 등록된 이름이 있습니다')
    else:
        sql2 = f"INSERT INTO gell(name, password, count) VALUES('{gell.name}', '{gell.password}', {gell.count})"
        db2.execute(sql2)
        return commonResponse(201)


@app.post('/gell/login', status_code=200, tags=["gellgell"], summary="gellgell 로그인")
async def postGellLogin(gell: gellName):
    sql1 = f"SELECT count(*) as cnt FROM gell WHERE name = '{gell.name}' and password = '{gell.password}'"
    res = db2.execute(sql1)
    count = res.fetchone()[0]

    if count > 0:
        return commonResponse(200)
    else:
        return commonResponse(404, 'DATA_EMPTY', '아이디/비밀번호를 다시 확인해주세요.')


@app.post('/gell/merge', status_code=200, tags=["gellgell"], summary="gellgell 계정 합치기")
async def postGellMerge(gell: gellMerge):
    sql1 = f"SELECT count(*) as cnt FROM gell WHERE name = '{gell.name}' and password = '{gell.password}'"
    res = db2.execute(sql1)
    count = res.fetchone()[0]

    if count > 0:
        sql2 = f"SELECT (SELECT count FROM gell WHERE name = '{gell.target_name}') as origin_count, (SELECT count FROM gell WHERE name = '{gell.name}') as into_count"
        res = db2.execute(sql2)
        data = res.fetchone()
        sum_count = data[0] + data[1]

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sql3 = f"UPDATE gell SET count = {sum_count} WHERE name = '{gell.target_name}'"
        sql4 = f"UPDATE gell SET del_stat = 1, del_datetime = '{now}' WHERE name = '{gell.name}'"
        db2.execute(sql3)
        db2.execute(sql4)
        return commonResponse(200)
    else:
        return commonResponse(404, 'DATA_EMPTY', '아이디/비밀번호를 다시 확인해주세요.')


@app.post('/gell/token', status_code=200, tags=["gellgell"], summary="gellgell CSRF Token 발급")
async def postGellToken(gell: gellToken):
    sql1 = "SELECT REPLACE(UUID(), '-', '') as token"
    res = db2.execute(sql1)
    token = res.fetchone()[0]

    sql2 = f"SELECT count(*) as cnt, idx FROM gell WHERE name = '{gell.name}' and password = '{gell.password}' and del_stat = 0"
    res2 = db2.execute(sql2)
    cnt = res2.fetchone()

    if cnt[0] > 0:
        sql3 = f"UPDATE gell SET csrf_token = '{token}' WHERE name = '{gell.name}'"
        db2.execute(sql3)
        return commonResponse(200, data={"csrf_token": token, "idx": cnt[1]})
    else:
        return commonResponse(401, 'UNAUTHORIZED', '아이디, 비밀번호를 확인해주세요.')


@app.get('/gell/ranking', status_code=200, tags=["gellgell"], summary="gellgell 랭킹")
async def getGellRanking():
    sql = "SELECT name, count, DATE_FORMAT(edit_datetime, '%%Y-%%m-%%d %%H:%%i:%%s') as edit_datetime FROM gell WHERE del_stat = 0 ORDER BY count DESC"
    res = db2.execute(sql)
    data = res.fetchall()
    result = sqlAlchemyRowToDict(data)
    return commonResponse(200, data=result)


@app.get('/gell/{idx}', status_code=200, tags=["gellgell"], summary="gellgell 특정 유저 검색")
async def getGellIdx(idx: int):
    sql = f"SELECT name, count, DATE_FORMAT(edit_datetime, '%%Y-%%m-%%d %%H:%%i:%%s') as edit_datetime FROM gell WHERE idx = {idx} and del_stat = 0"
    res = db2.execute(sql)
    data = res.fetchone()

    if data is None:
        return commonResponse(404, 'DATA_EMPTY', '해당되는 이름이 없습니다.')

    sql2 = "SELECT name, count, DATE_FORMAT(edit_datetime, '%%Y-%%m-%%d %%H:%%i:%%s') as edit_datetime FROM gell WHERE del_stat = 0 ORDER BY count DESC"
    res2 = db2.execute(sql2)
    data2 = res2.fetchall()
    result = sqlAlchemyRowToDict(data2)
    rank = 0

    for r in result:
        rank += 1
        if r['name'] == data[0]:
            break

    result = {
        "count": data[1],
        "edit_datetime": data[2],
        "rank": rank
    }
    return commonResponse(200, data=result)


if __name__ == '__main__':
    uvicorn.run("main:app", host="0.0.0.0", port=9091, reload=True)
    # getInfo()
