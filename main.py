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
import redis
import uuid
import sentry_sdk
from sentry_sdk.integrations.asgi import SentryAsgiMiddleware


dotenv.load_dotenv()
env = os.getenv('ENV')
dbinfo = os.getenv('SQLADDR')
dbinfo2 = os.getenv('SQLADDR2')
jwtSalt = os.getenv('JWT_SALT')
db = create_engine(dbinfo)
db.execute("SET time_zone='Asia/Seoul'")
db2 = create_engine(dbinfo2)
db2.execute("SET time_zone='Asia/Seoul'")

sentry_sdk.init(dsn=os.getenv('DSN'))

if env == 'PROD':
    REDIS_HOST = str = os.getenv("REDIS_HOST")
    REDIS_PORT = integer = os.getenv("REDIS_PORT")
else:
    REDIS_HOST = os.getenv("REDIS_LOCAL_HOST")
    REDIS_PORT = os.getenv("REDIS_LOCAL_PORT")
rd = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)

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
    "https://junharry-test.vercel.app",
    "https://junharry.com",
    "https://www.junharry.com",
    "https://junharry-git-develop-haenu.vercel.app",
    "https://junharry.com",
    "https://test.junharry.com",
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
            return [200, 'SUCCESS', '성공', payload]
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


@app.get('/junharry/test', tags=["전해리 방송일정"], summary="해리배치고사 결과들")
async def getJunharryTest(X_Access_Token: str = Header(None)):
    if X_Access_Token is None or X_Access_Token == 'null':
        return commonResponse(401, 'TOKEN_NOT_PROVIDED', '로그인 정보가 없습니다. 다시 로그인해주세요')
    validation_result = await common_token_validation(X_Access_Token)
    if validation_result[0] != 200:
        return commonResponse(validation_result[0], validation_result[1], validation_result[2])

    # 캐시 조회
    totalRedisKey = f"junharry_test_total"
    totalRedisData = rd.get(totalRedisKey)
    if totalRedisData is not None:
        totalRedisData = json.loads(totalRedisData)
        return commonResponse(200, data=totalRedisData)

    # 먼저 전체 응시자 조회
    sql = f"SELECT user_idx, DATE_FORMAT(reg_datetime, '%%Y-%%m-%%d %%H:%%i:%%s') as reg_datetime, DATE_FORMAT(edit_datetime, '%%Y-%%m-%%d %%H:%%i:%%s') as edit_datetime FROM harrytest_userjoin WHERE is_done = 1 and del_stat = 0"
    res = db2.execute(sql)
    data = res.fetchall()
    
    # getInternalJunharryTestResult 호출
    total = []
    for row in data:
        # row[0] 없을 때 예외처리
        if row is None:
            continue
        redisKey = f"harrytest_score:{row[0]}"
        redisData = rd.get(redisKey)
        if redisData is not None:
            redisData = json.loads(redisData)
            total.append(redisData)
        # 응시 결과 조회
        score = await getInternalJunharryScore(row[0])
        # user data 조회
        sql = f"SELECT id, name, display_name, description, profile_image_url, twitch_refresh_token as email, DATE_FORMAT(created_at, '%%Y-%%m-%%d %%H:%%i:%%s') as created_at FROM harrytest_users WHERE id = {row[0]}"
        res = db2.execute(sql)
        userData = res.fetchone()
        if userData is None:
            continue
        # 최종 데이터 조합
        user_id = userData[0]
        user_name = userData[1]
        user_display_name = userData[2]
        user_description = userData[3]
        user_profile_image_url = userData[4]
        user_email = userData[5]
        user_created_at = userData[6]
        reUserData = {
            "user_id": user_id,
            "user_name": user_name,
            "user_display_name": user_display_name,
            "user_description": user_description,
            "user_profile_image_url": user_profile_image_url,
            "user_email": user_email,
            "user_created_at": user_created_at,
        }
        inputData = {
            "user": reUserData,
            "score": score
        }
        rd.set(redisKey, json.dumps(inputData))
        total.append(inputData)

    # set cache
    rd.set(totalRedisKey, json.dumps(total), 180)

    return commonResponse(200, data=total)


class HarryTestTwitchDto(BaseModel):
    code: str


@app.post('/junharry-test/auth', tags=["해리배치고사"], summary="해리배치고사 토큰 발급")
async def postJunharryTestToken(data: HarryTestTwitchDto):
    twitchClientId = os.getenv('TWITCH_CLIENT_ID')
    twitchClientSecret = os.getenv('TWITCH_CLIENT_SECRET')
    twitchRedirectUri = 'https://api-v1.leaven.team/junharry-test/auth'
    url = f"https://id.twitch.tv/oauth2/token?client_id={twitchClientId}&client_secret={twitchClientSecret}&code={data.code}&grant_type=authorization_code&redirect_uri={twitchRedirectUri}"
    res = requests.post(url)
    print(res.json())
    if res.status_code == 200:
        # set data
        twitch_data = res.json()

        twitch_access_token = twitch_data['access_token']
        twitch_refresh_token = twitch_data['refresh_token']

        apiData = updateTwitchUserInfo(twitch_access_token)

        twitch_id = apiData['id']
        name = apiData['login']
        display_name = apiData['display_name']
        description = apiData['description']
        profile_image_url = apiData['profile_image_url']
        offline_image_url = apiData['offline_image_url']
        email = apiData['email']
        created_at = apiData['created_at'].replace('T', ' ').replace('Z', '')
        type = apiData['type']
        broadcaster_type = apiData['broadcaster_type']
        

        # Check DB and insert if not exist
        sql = f"SELECT count(*) as cnt FROM harrytest_users WHERE id = {twitch_id}"
        db_res = db2.execute(sql)
        data = db_res.fetchone()
        count = data[0]
        if count == 0:
            sql = f"INSERT INTO harrytest_users (id, name, display_name, description, profile_image_url, offline_image_url, created_at, twitch_access_token, email, twitch_refresh_token, type, broadcaster_type) VALUES (" + \
                f"{twitch_id}, '{name}', '{display_name}', '{description}', '{profile_image_url}', '{offline_image_url}', '{created_at}', '{twitch_access_token}', '{twitch_refresh_token}', '{email}', '{type}', '{broadcaster_type}')"
            db2.execute(sql)

        # Create a new token
        jwtData = {
            "user_id": twitch_id,
            "expire": int((str(time.time())).split('.')[0]) + 1209600
        }
        token = jwt.encode(jwtData, jwtSalt)
        return commonResponse(200, data={"token": token})
    else:
        return commonResponse(401, 'Unauthorized', '트위치 인증에 실패했습니다.')


@app.get('/junharry-test/home', tags=["해리배치고사"], summary="해리배치고사 Home")
async def getJunharryTestGroup(X_Access_Token: str = Header(None)):
    if X_Access_Token is None or X_Access_Token == 'null':
        return commonResponse(401, 'TOKEN_NOT_PROVIDED', '로그인 정보가 없습니다. 다시 로그인해주세요')
    validation_result = await common_token_validation(X_Access_Token)
    if validation_result[0] != 200:
        return commonResponse(validation_result[0], validation_result[1], validation_result[2])

    user_idx = validation_result[3]['user_id']

    # Get User Info
    sql = f"SELECT id, name, display_name, profile_image_url FROM harrytest_users WHERE id = {user_idx}"
    res = db2.execute(sql)
    data = res.fetchone()

    # Check is done
    sql = f"SELECT is_done FROM harrytest_userjoin WHERE user_idx = {user_idx}"
    res = db2.execute(sql)
    data2 = res.fetchone()

    if data2 is None:
        is_done = 0
    elif data2[0] == 0:
        is_done = 0
    else:
        is_done = 1


    # User Info
    responseData = {
        "user": {
            "name": data[1],
            "display_name": data[2],
            "logo": data[3]
        },
        "is_done": is_done
    }

    return commonResponse(200, data=responseData)


@app.post('/junharry-test/start/{group_idx}', tags=["해리배치고사"], summary="해리배치고사 시작")
async def postJunharryTestStart(group_idx: int, X_Access_Token: str = Header(None)):
    if X_Access_Token is None or X_Access_Token == 'null':
        return commonResponse(401, 'TOKEN_NOT_PROVIDED', '로그인 정보가 없습니다. 다시 로그인해주세요')
    validation_result = await common_token_validation(X_Access_Token)
    if validation_result[0] != 200:
        return commonResponse(validation_result[0], validation_result[1], validation_result[2])

    user_idx = validation_result[3]['user_id']

    # 참여 기록이 있는지 확인
    sql = f"SELECT count(*) as cnt FROM harrytest_userjoin WHERE user_idx = {user_idx} and group_idx = {group_idx}"
    res = db2.execute(sql)
    data = res.fetchone()
    count = data[0]
    if count == 0:
        sql = f"INSERT INTO harrytest_userjoin (user_idx, group_idx) VALUES ({user_idx}, {group_idx})"
        db2.execute(sql)

    # CSRF 토큰 부여하고 성공 반환 (그럼 프론트에서 1번 문제 호출하러 가면서 토큰 같이 보내서 처리)
    csrf_token = str(uuid.uuid4()).replace('-', '')
    sql = f"UPDATE harrytest_users SET csrf_token = '{csrf_token}' WHERE id = {user_idx}"
    db2.execute(sql)

    returnData = {
        "csrf_token": csrf_token
    }

    if len(data) == 0:
        return commonResponse(400, 'NO_DATA', '데이터가 없습니다.')
    else:
        return commonResponse(200, data=returnData)


@app.post('/junharry-test/end', tags=["해리배치고사"], summary="해리배치고사 종료")
async def postJunharryTestEnd(X_Access_Token: str = Header(None), X_CSRF_Token: str = Header(None)):
    if X_Access_Token is None or X_Access_Token == 'null':
        return commonResponse(401, 'TOKEN_NOT_PROVIDED', '로그인 정보가 없습니다. 다시 로그인해주세요')

    if X_CSRF_Token is None or X_CSRF_Token == 'null':
        return commonResponse(401, 'CSRF_TOKEN_NOT_PROVIDED', 'CSRF 토큰이 없습니다. 다시 시도해주세요')

    validation_result = await common_token_validation(X_Access_Token)
    if validation_result[0] != 200:
        return commonResponse(validation_result[0], validation_result[1], validation_result[2])
    user_idx = validation_result[3]['user_id']

    get_csrf_query = f"SELECT csrf_token FROM harrytest_users WHERE id = {user_idx}"
    res = db2.execute(get_csrf_query)
    data = res.fetchone()
    if data[0] != X_CSRF_Token:
        return commonResponse(401, 'CSRF_TOKEN_NOT_MATCH', 'CSRF 토큰이 일치하지 않습니다. 다시 시도해주세요')

    # 종료 처리
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sql = f"UPDATE harrytest_userjoin SET is_done = 1, edit_datetime = '{now}' WHERE user_idx = {user_idx}"
    db2.execute(sql)

    return commonResponse(200)


@app.get('/junharry-test/question/{group}/{question}', tags=["해리배치고사"], summary="해리배치고사 문제 조회")
async def getJunharryTestQuestion(X_Access_Token: str = Header(None), X_CSRF_Token: str = Header(None), group: int = '', question: int = ''):
    if X_Access_Token is None or X_Access_Token == 'null':
        return commonResponse(401, 'TOKEN_NOT_PROVIDED', '로그인 정보가 없습니다. 다시 로그인해주세요')
    if X_CSRF_Token is None or X_CSRF_Token == 'null':
        return commonResponse(401, 'CSRF_TOKEN_NOT_PROVIDED', 'CSRF 토큰이 없습니다. 다시 시도해주세요')

    validation_result = await common_token_validation(X_Access_Token)
    if validation_result[0] != 200:
        return commonResponse(validation_result[0], validation_result[1], validation_result[2])
    user_idx = validation_result[3]['user_id']

    get_csrf_query = f"SELECT csrf_token FROM harrytest_users WHERE id = {user_idx}"
    res = db2.execute(get_csrf_query)
    data = res.fetchone()
    if data[0] != X_CSRF_Token:
        return commonResponse(401, 'CSRF_TOKEN_NOT_MATCH', 'CSRF 토큰이 일치하지 않습니다. 다시 시도해주세요')

    # 문제 조회
    sql = f"SELECT subject FROM harrytest_question WHERE idx = {question}"
    res = db2.execute(sql)
    data = res.fetchone()
    if len(data) == 0:
        return commonResponse(400, 'NO_DATA', '데이터가 없습니다.')

    # 답변 조회
    sql2 = f"SELECT idx, content FROM harrytest_answer WHERE question_idx = {question}"
    res = db2.execute(sql2)
    data2 = res.fetchall()
    if len(data2) == 0:
        return commonResponse(400, 'NO_DATA', '데이터가 없습니다.')

    # 미리 등록된 답변 있는지 조회
    sql3 = f"SELECT user_answer_idx FROM harrytest_userdata WHERE user_idx = {user_idx} and question_idx = {question} order by idx desc"
    res = db2.execute(sql3)
    data3 = res.fetchone()
    if data3 is None:
        user_answer = -1
    else:
        user_answer = data3[0]

    # CSRF 토큰 부여하고 업데이트
    csrf_token = str(uuid.uuid4()).replace('-', '')
    sql = f"UPDATE harrytest_users SET csrf_token = '{csrf_token}' WHERE id = {user_idx}"
    db2.execute(sql)

    returnData = {
        "question": data[0],
        "answers": sqlAlchemyRowToDict(data2),
        "answer": user_answer,
        "csrfToken": csrf_token
    }

    return commonResponse(200, data=returnData)


@app.post('/junharry-test/submit/{group}/{question}/{answer}', tags=["해리배치고사"], summary="해리배치고사 문제 정답 등록")
async def postJunharryTestSubmit(X_Access_Token: str = Header(None), X_CSRF_Token: str = Header(None), group: int = -1, question: int = -1, answer: int = -1):
    if group == -1 or question == -1 or answer == -1:
        return commonResponse(400, 'UNEXPECTED_VALUE_GIVEN', '데이터가 잘못 전달되었습니다.')
    if X_Access_Token is None or X_Access_Token == 'null':
        return commonResponse(401, 'TOKEN_NOT_PROVIDED', '로그인 정보가 없습니다. 다시 로그인해주세요')

    validation_result = await common_token_validation(X_Access_Token)
    if validation_result[0] != 200:
        return commonResponse(validation_result[0], validation_result[1], validation_result[2])
    user_idx = validation_result[3]['user_id']

    get_csrf_query = f"SELECT csrf_token FROM harrytest_users WHERE id = {user_idx}"
    res = db2.execute(get_csrf_query)
    data = res.fetchone()
    if data[0] != X_CSRF_Token:
        return commonResponse(401, 'CSRF_TOKEN_NOT_MATCH', 'CSRF 토큰이 일치하지 않습니다. 다시 시도해주세요')

    # 답변 입력
    try:
        sql = f"INSERT INTO harrytest_userdata (user_idx, question_idx, user_answer_idx) VALUES ({user_idx}, {question}, {answer})"
        db2.execute(sql)
    except Exception as e:
        return commonResponse(400, 'DB_ERROR', '데이터베이스 오류가 발생했습니다.')

    return commonResponse(200)


@app.get('/junharry-test/result/{group}', tags=["해리배치고사"], summary="해리배치고사 결과 조회")
async def getJunharryTestResult(X_Access_Token: str = Header(None), group: int = -1):
    if group == -1:
        return commonResponse(400, 'UNEXPECTED_VALUE_GIVEN', '데이터가 잘못 전달되었습니다.')
    if X_Access_Token is None or X_Access_Token == 'null':
        return commonResponse(401, 'TOKEN_NOT_PROVIDED', '로그인 정보가 없습니다. 다시 로그인해주세요')
    
    validation_result = await common_token_validation(X_Access_Token)
    if validation_result[0] != 200:
        return commonResponse(validation_result[0], validation_result[1], validation_result[2])
    user_idx = validation_result[3]['user_id']

    redisKey = f"harrytest_result:{user_idx}"
    redisData = rd.get(redisKey)
    if redisData is not None:
        redisData = json.loads(redisData)
        return commonResponse(200, data=redisData)


    # is_done 이 0이면 오류 반환
    sql = f"SELECT is_done FROM harrytest_userjoin WHERE user_idx = {user_idx}"
    res = db2.execute(sql)
    data0 = res.fetchone()
    if data0 is None:
        return commonResponse(400, 'NOT_DONE', '아직 해리배치고사에 응시하지 않았습니다.')
    if data0[0] == 0:
        return commonResponse(400, 'NOT_DONE', '아직 해리배치고사를 완료하지 않았습니다.')

    # 유저 데이터 조회
    sql = f"SELECT name, display_name, profile_image_url FROM harrytest_users WHERE id = {user_idx}"
    res = db2.execute(sql)
    data = res.fetchone()
    if data is None:
        return commonResponse(400, 'NO_DATA', '데이터가 없습니다.')

    # 전체 데이터 조회
    data_list = []
    score = 0
    for i in range(15):
        # 정답 조회
        answer_list = []
        sql = f"SELECT idx, content FROM harrytest_answer WHERE question_idx = {i+1}"
        res = db2.execute(sql)
        data2 = res.fetchall()
        if data2 is None:
            return commonResponse(400, 'NO_DATA', '데이터가 없습니다.')
        else:
            answer_list.append(sqlAlchemyRowToDict(data2))

        # 문제 조회
        sql = f"SELECT subject, answer_idx FROM harrytest_question WHERE idx = {i+1}"
        res = db2.execute(sql)
        data3 = res.fetchone()
        if data3 is None:
            return commonResponse(400, 'NO_DATA', '데이터가 없습니다.')

        # 유저 정답 조회
        sql = f"SELECT user_answer_idx FROM harrytest_userdata WHERE user_idx = {user_idx} AND question_idx = {i+1} ORDER BY idx DESC LIMIT 1"
        res = db2.execute(sql)
        data4 = res.fetchone()
        if data4 is None:
            return commonResponse(400, 'NO_DATA', '데이터가 없습니다.')
        
        # 전체 데이터 결합
        total_data = {
            "question_idx": i+1,
            "question": data3[0],
            "correct_answer": data3[1],
            "user_answer": data4[0],
            "answers": answer_list
        }
        data_list.append(total_data)

        # 점수 계산
        if data3[1] == data4[0]:
            score += 1

    returnData = {
        "user_data": {
            "name": data[0],
            "display_name": data[1],
            "profile_image_url": data[2]
        },
        "score": score,
        "test_data": data_list
    }

    # redis 저장
    rd.set(redisKey, json.dumps(returnData))

    return commonResponse(200, data=returnData)


async def getInternalJunharryScore(user_idx: int = -1):
    # is_done 이 0이면 오류 반환
    sql = f"SELECT is_done FROM harrytest_userjoin WHERE user_idx = {user_idx}"
    res = db2.execute(sql)
    data0 = res.fetchone()
    if data0 is None:
        return commonResponse(400, 'NOT_DONE', '아직 해리배치고사에 응시하지 않았습니다.')
    if data0[0] == 0:
        return commonResponse(400, 'NOT_DONE', '아직 해리배치고사를 완료하지 않았습니다.')

    # 전체 데이터 조회
    score = 0
    for i in range(15):
        # 문제 조회
        sql = f"SELECT subject, answer_idx FROM harrytest_question WHERE idx = {i+1}"
        res = db2.execute(sql)
        data3 = res.fetchone()
        if data3 is None:
            return commonResponse(400, 'NO_DATA', '데이터가 없습니다.')

        # 유저 정답 조회
        sql = f"SELECT user_answer_idx FROM harrytest_userdata WHERE user_idx = {user_idx} AND question_idx = {i+1} ORDER BY idx DESC LIMIT 1"
        res = db2.execute(sql)
        data4 = res.fetchone()
        if data4 is None:
            return commonResponse(400, 'NO_DATA', '데이터가 없습니다.')

        # 점수 계산
        if data3[1] == data4[0]:
            score += 1

    return score


def updateTwitchUserInfo(access_token):
    url = 'https://api.twitch.tv/helix/users'
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Client-ID': os.getenv('TWITCH_CLIENT_ID')
    }
    res = requests.get(url, headers=headers)
    if res.status_code != 200:
        return None
    else:
        data = res.json()['data']
        return data[0]
    

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
