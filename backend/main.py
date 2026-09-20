"""docXray API — 바깥에서 부르는 창구.

    POST /scan            파일 여러 개 업로드 -> ScanBatch JSON   (D가 호출)
    POST /mask            화면에서 고른 항목만 마스킹한 사본 생성
    POST /samples/mask    샘플 문서에서 고른 항목만 마스킹한 사본 생성
    POST /scan/text       문장 하나 -> ScanResult JSON            (C의 실시간 답장 스캔)
    PATCH /scan-results/{scan_result_id}/hidden-commands/{finding_ref}
                          숨은 명령 확인/제거/무시 상태 기록 (DB 저장 켜져 있을 때만 동작)
    GET  /masking/options 화면용 마스킹 방식·유형 기준표
    GET  /download/{id}   마스킹 사본 파일 하나
    GET  /download/all    배치 전체 .zip
    GET  /samples         심사위원용 샘플을 미리 검사한 결과
    GET  /health          살아있는지 확인
    /training/*           훈련 모드(C, backend/training/router.py). 붙지 못하면 /health에 사유 표시

지켜야 하는 것
--------------
1. **업로드 원본은 처리 후 즉시 지운다.** 개인정보 보호 서비스가 개인정보를 모으면
   그 자체로 실격 사유다(backend/scanner/README.md). 임시 파일로 받아 스캔하고
   finally에서 삭제한다.

2. **마스킹 사본은 TTL이 지나면 지운다.** scan_results의 masked_path는 서버 임시
   경로이고 다운로드 후 남아 있을 이유가 없다. 응답 직후에 지우면 다운로드를 할 수
   없으므로(스캔과 다운로드는 별개 요청이다) 발급 시각을 기록해 두고 만료된 것부터
   지운다.

3. **경로를 사용자 입력으로 만들지 않는다.** /download/{id}의 id는 우리가 발급한
   UUID이고, 실제 경로는 레지스트리에서만 꺼낸다. 클라이언트가 보낸 문자열을 경로로
   이어 붙이면 ../../로 서버 파일을 읽어갈 수 있다.

4. **로그에 원문을 남기지 않는다.** 탐지된 값도, 파일 내용도 찍지 않는다(팀 규칙).

DB는 없어도 돈다. .env가 없는 환경에서도 스캔은 되어야 하므로 저장은 선택이다.
"""

from __future__ import annotations

import logging
import json
import os
import re
import shutil
import tempfile
import threading
import time
import uuid
import zipfile
from collections import Counter
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass
from typing import Literal

from fastapi import FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from starlette.background import BackgroundTask

from backend.scanner import scan
from backend.scanner.masking import policy as mask_policy
from backend.shared import schema
from backend.shared.logging_config import (
    configure_logging,
    get_logger,
    log_event,
    reset_request_id,
    set_request_id,
)

configure_logging()
logger = get_logger(__name__)

# 훈련 모드 라우터(C). **임시 조치 — C가 고치면 이 try/except를 걷어낸다.**
#
# backend/training/의 두 모듈이 import 순간 외부 AI 클라이언트를 만든다 —
# training_flow.py(AttackerService, ANTHROPIC_API_KEY 필요)와 defender.py(OpenAI,
# OPENAI_API_KEY 필요). 키가 없으면 그 예외가 여기까지 타고 올라와 **app 객체 자체가
# 만들어지지 않았다** — 훈련 모드만이 아니라 /health·/scan·/download까지 전부
# 죽었다(2026-09-13·14 실측).
#
# 이 파일 맨 위에 적어둔 "DB는 없어도 돈다. .env가 없는 환경에서도 스캔은 되어야
# 한다"는 원칙이 깨지는 자리다. 스캐너는 키 없이도 떠야 하므로, 훈련 모드를 못
# 붙이면 그 단계만 건너뛴다 — ner.py·models.py·id_detector.py가 모델을 지연
# 로딩하는 것과 같은 이유다.
#
# 근본 해결은 C 쪽에서 두 클라이언트를 첫 호출 때 만드는 것이다. 그렇게 바뀌면
# 여기서 예외가 나지 않으므로 이 코드는 그대로 둬도 정상 동작한다. 지금 붙었는지와
# 못 붙은 이유는 /health의 training_mode·training_mode_error로 확인한다.
try:
    from backend.training.router import router as training_router
except Exception as exc:  # 키 없음, DB 미설정, C 모듈 오류 등 무엇이든
    training_router = None
    _TRAINING_ROUTER_ERROR = f"{type(exc).__name__}: {exc}"
else:
    _TRAINING_ROUTER_ERROR = ""

# 검사 결과 집계 저장(선택). 이 파일 맨 위 원칙("DB는 없어도 돈다")과 같은 이유로
# 임포트 자체를 try/except로 감싼다 — TiDB 자격증명이 없는 로컬/평가 환경에서도
# 스캐너는 그대로 떠야 한다. 실패하면 _persist_scan_results가 조용히 아무 것도
# 안 하는 쪽으로 떨어진다.
try:
    from backend.db.session import SessionLocal, init_db
    from backend.db.converters import save_scan_result
    from backend.db.lock_reaper import kill_stale_transactions
    from backend.db.seed_demo_user import DEMO_USER_ID, ensure_demo_user
    from backend.db.tables import FindingRow
except Exception as exc:  # noqa: BLE001
    SessionLocal = None
    init_db = None
    save_scan_result = None
    kill_stale_transactions = None
    ensure_demo_user = None
    FindingRow = None
    DEMO_USER_ID = 1
    _DB_ERROR = f"{type(exc).__name__}: {exc}"
else:
    _DB_ERROR = ""


def _init_db_best_effort() -> None:
    """앱이 뜰 때 테이블·데모 유저를 준비한다. 실패해도 서버는 그대로 뜬다.

    클린 DB(테이블이 하나도 없는 새 배포)에 지금 이걸 안 하면, ScanResultRow가
    user_id=DEMO_USER_ID로 FK를 거는데 그 유저가 없어서 _persist_scan_results가
    매번 조용히 실패한다 — 심사 환경을 새로 배포했을 때 딱 이 꼴로 터진다
    (로그에만 남고 사용자·심사위원 화면에는 아무 표시도 없다).
    init_db()는 create_all이라 이미 테이블이 있어도 안전하게 다시 부를 수 있다.
    """
    if init_db is None or ensure_demo_user is None:
        return
    try:
        init_db()
        ensure_demo_user()
    except Exception as exc:  # noqa: BLE001
        log_event(logger, logging.WARNING, "db.init.failed", error_code=type(exc).__name__)


def _persist_scan_results(results: list[schema.ScanResult]) -> None:
    """검사 결과를 집계용으로 최선을 다해 저장한다. 실패해도 스캔 응답은 그대로 나간다.

    아직 로그인/세션이 없어서 전부 데모 계정(DEMO_USER_ID)으로 쌓는다 — 여러 사용자를
    구분하는 일은 인증이 생긴 뒤의 문제다. save_scan_result 자체가 원문·마스킹 사본은
    저장하지 않고 집계(위험점수, 유형별 건수)만 남기도록 설계돼 있다(db/converters.py).
    """
    if SessionLocal is None or save_scan_result is None:
        return
    db = SessionLocal()
    try:
        for result in results:
            row = save_scan_result(db, DEMO_USER_ID, result, file_extension=result.file_type)
            result.db_id = row.id  # save_scan_result가 flush까지 해서 이 시점에 이미 채워져 있다
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        for result in results:
            result.db_id = None  # 커밋이 안 됐으니 방금 채운 id는 무효다
        log_event(logger, logging.WARNING, "scan.persist.failed", error_code=type(exc).__name__)
    finally:
        db.close()


MASKED_DIR_PREFIX = "infoguard_mask_"


# 워커 하나가 실제 요청 처리 중(DB 트랜잭션을 연 채) 컨테이너가 재시작되면
# (배포 중 크래시, Railway의 강제 재시작 등) 그 연결은 TiDB 쪽에 커밋도 롤백도
# 안 된 채 남는다 — TCP가 끊긴 걸 TiDB가 스스로 알아채기 전까지는(서버 쪽
# wait_timeout이 길다) 그 트랜잭션이 잡은 락이 풀리지 않는다. 실측(2026-09-20):
# PR #60의 미해결 머지 충돌로 배포가 502 크래시 루프를 도는 동안 이런 트랜잭션이
# 하나 생겨 15분 넘게 방치됐고, training_progress에 새로 쓰는 모든 요청이
# "Lock wait timeout exceeded"로 막혔다. 애플리케이션 코드는 정상 종료 경로에서
# 전부 db.close()를 부르고 있어(get_session()의 finally) 새는 곳이 없다 — 문제는
# **비정상** 종료라 코드로 막을 수 없고, 대신 주기적으로 방치된 트랜잭션을 찾아
# 직접 끊는 쪽(backend/db/lock_reaper.py)으로 안전망을 둔다.
_LOCK_REAPER_INTERVAL_SECONDS = 60


def _run_lock_reaper_forever() -> None:
    if SessionLocal is None or kill_stale_transactions is None:
        return
    while True:
        time.sleep(_LOCK_REAPER_INTERVAL_SECONDS)
        try:
            db = SessionLocal()
            try:
                killed = kill_stale_transactions(db)
                if killed:
                    log_event(logger, logging.WARNING, "db.lock_reaper.swept", removed_count=killed)
            finally:
                db.close()
        except Exception as exc:  # noqa: BLE001 — 백그라운드 스레드라 여기서 잡지 않으면 조용히 사라진다
            log_event(logger, logging.DEBUG, "db.lock_reaper.sweep_failed", error_code=type(exc).__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """서버가 뜰 때 이전 프로세스가 남긴 사본을 한 번 훑어 지우고, 방치된 DB
    트랜잭션을 주기적으로 끊는 백그라운드 스레드를 띄운다.

    사본 경로는 메모리(_masked_files)에만 있어서 재시작하면 레지스트리는 비는데
    **파일은 디스크에 그대로 남는다.** 그 뒤로는 아무도 존재를 모르니 _sweep_expired의
    TTL 청소에도 걸리지 않고 영영 쌓인다(실측으로 확인했다 — 개발 중에만 527개가
    쌓여 있었다).

    남는 것이 마스킹된 사본이라 원본만큼 위험하진 않지만, 개인정보가 일부라도
    담긴 파일이 서버에 무기한 남아서는 안 된다.
    """
    removed = _sweep_orphan_dirs()
    _init_db_best_effort()
    threading.Thread(target=_run_lock_reaper_forever, daemon=True).start()
    log_event(
        logger,
        logging.INFO,
        "service.started",
        removed_count=removed,
        training_mode="on" if training_router is not None else "off",
        db_mode="on" if SessionLocal is not None else "off",
    )
    yield
    log_event(logger, logging.INFO, "service.stopped")


app = FastAPI(title="docXray API", version=schema.SCHEMA_VERSION, lifespan=lifespan)


def _swagger_compatible_openapi() -> dict:
    """Swagger UI가 UploadFile을 실제 파일 선택기로 표시하도록 보완한다.

    현재 FastAPI/Pydantic 조합은 바이너리 필드를 OpenAPI 3.1의
    contentMediaType으로 표현한다. Railway의 Swagger UI는 이 표기를 문자열
    입력으로 렌더링하므로, 널리 지원되는 format=binary를 함께 제공한다.
    """
    if app.openapi_schema is not None:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        openapi_version=app.openapi_version,
        routes=app.routes,
    )

    def add_binary_format(node) -> None:
        if isinstance(node, dict):
            if (
                node.get("type") == "string"
                and node.get("contentMediaType") == "application/octet-stream"
            ):
                node["format"] = "binary"
            for value in node.values():
                add_binary_format(value)
        elif isinstance(node, list):
            for value in node:
                add_binary_format(value)

    add_binary_format(openapi_schema)
    app.openapi_schema = openapi_schema
    return openapi_schema


app.openapi = _swagger_compatible_openapi

# Training Mode API 연결. 못 붙였으면 스캐너만 띄운다(위 import 주석 참고).
if training_router is not None:
    app.include_router(training_router)

# 쉼표로 구분한 프론트 주소만 허용한다. 로컬 기본값은 Vite 개발 서버이고,
# Railway에서는 ALLOWED_ORIGINS=https://<vercel-domain> 형태로 넣는다.
_allowed_origins = [
    origin.strip().rstrip("/")
    for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def privacy_safe_access_log(request: Request, call_next):
    """Log request metadata without bodies, query strings, or opaque tokens."""
    request_id = uuid.uuid4().hex
    token = set_request_id(request_id)
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception as exc:
        duration_ms = round((time.perf_counter() - started) * 1000, 1)
        route = getattr(request.scope.get("route"), "path", "unmatched")
        log_event(
            logger,
            logging.ERROR,
            "http.request.failed",
            method=request.method,
            route=route,
            status_code=500,
            duration_ms=duration_ms,
            error_code=type(exc).__name__,
        )
        raise
    else:
        duration_ms = round((time.perf_counter() - started) * 1000, 1)
        route = getattr(request.scope.get("route"), "path", "unmatched")
        level = logging.WARNING if response.status_code >= 400 else logging.INFO
        log_event(
            logger,
            level,
            "http.request.completed",
            method=request.method,
            route=route,
            status_code=response.status_code,
            duration_ms=duration_ms,
        )
        response.headers["X-Request-ID"] = request_id
        return response
    finally:
        reset_request_id(token)

# 업로드 1건 상한. 이걸 안 걸면 큰 파일 하나로 디스크를 채울 수 있다.
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
MAX_FILES_PER_REQUEST = 10
# 훈련 모드 답장 스캔의 입력 상한. NER이 긴 글을 청킹하므로 길이 자체는 문제가
# 아니지만, 채팅 한 줄에 소설이 들어올 이유는 없다.
MAX_TEXT_LENGTH = 100_000
# 마스킹 사본 보관 시간. 사용자가 결과를 보고 내려받기까지의 여유다.
MASKED_FILE_TTL_SECONDS = 30 * 60
# 비동기 검사 작업(진행 상태) 보관 시간. 폴링이 끝난 뒤에도 한동안은 남겨 둬서
# 화면이 마지막 폴링을 놓쳐도(탭 백그라운드 등) 뒤늦게 결과를 받아갈 수 있게 한다.
SCAN_JOB_TTL_SECONDS = 30 * 60


# ---------------------------------------------------------------------------
# 마스킹 사본 레지스트리
# ---------------------------------------------------------------------------
#
# 스캔과 다운로드는 별개 요청이라 사본 경로를 기억해야 한다. 프로세스 메모리에
# 두므로 서버를 재시작하면 레지스트리가 비는데, **파일은 디스크에 그대로 남는다.**
# 그래서 재시작 직후 한 번 훑어 지운다(_sweep_orphan_dirs). 그 청소가 없으면
# 고아 파일이 TTL 청소에도 안 걸려 영영 쌓인다.


@dataclass
class _MaskedFile:
    path: str
    download_name: str
    created_at: float
    # 어느 검사(배치)에서 나온 사본인가. /download/all이 "이 배치의 것만 묶는다"를
    # 지킬 때 쓴다. 나중에 만든 부분 마스킹 사본도 원본과 같은 배치를 물려받는다.
    batch_id: str | None = None


_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")  # uuid4().hex의 모양


def _atomic_write_json(path: str, payload: dict | list) -> None:
    """쓰다 만 JSON을 다른 워커가 읽지 않도록 임시 파일에 쓰고 rename한다.

    os.replace는 같은 파일시스템 안에서 원자적이다. 단 Windows는 대상 파일을 다른
    스레드가 마침 읽는 중이면 잠깐 rename을 거부한다(POSIX에서는 문제없다).
    그 순간은 아주 짧으므로 몇 번만 재시도한다.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp_path = f"{path}.tmp{os.getpid()}"
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False)
    for attempt in range(5):
        try:
            os.replace(tmp_path, path)
            return
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(0.05)


class _SharedDict:
    """워커들이 같이 보는 dict. 값은 컨테이너 공용 디스크에 JSON으로 둔다.

    프로세스 메모리(dict)에 두면 안 되는 이유는 비동기 검사 job과 똑같다 —
    Dockerfile이 uvicorn을 --workers 4로 띄우므로 워커마다 별도 프로세스·별도
    메모리다. 사본을 만든 워커와 다운로드 요청을 받은 워커가 다르면(로드밸런서가
    고른다) 방금 만든 사본을 상대 워커는 전혀 모른다. 실측 2026-09-20: 검사는
    성공했는데 곧바로 누른 '사본 다운받기'가 404("사본이 없거나 보관 기간이
    지났습니다")로 떨어지고, 다시 만들면 될 때도 있고 안 될 때도 있었다.
    워커가 4개니 우연히 같은 워커에 걸리는 1/4만 성공한 것이다.

    키가 그대로 파일 이름이 된다. /download/{file_id}로 사용자 입력이 그대로
    들어오므로("../../etc/passwd" 등) 글자·숫자·`_`·`-`만 받는다. 실제로 쓰는
    키는 언제나 uuid4().hex다.
    """

    _KEY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

    def __init__(self, dirname: str, load, dump):
        self._dir = os.path.join(tempfile.gettempdir(), dirname)
        self._load = load
        self._dump = dump

    def _path(self, key) -> str:
        if not isinstance(key, str) or not self._KEY_PATTERN.match(key):
            raise KeyError(key)
        return os.path.join(self._dir, f"{key}.json")

    def get(self, key, default=None):
        try:
            path = self._path(key)
        except KeyError:
            return default
        try:
            with open(path, encoding="utf-8") as fh:
                return self._load(json.load(fh))
        except (FileNotFoundError, json.JSONDecodeError, TypeError, KeyError):
            return default

    def __getitem__(self, key):
        value = self.get(key)
        if value is None:
            raise KeyError(key)
        return value

    def __setitem__(self, key, value) -> None:
        _atomic_write_json(self._path(key), self._dump(value))

    def __contains__(self, key) -> bool:
        return self.get(key) is not None

    def pop(self, key, default=None):
        value = self.get(key, default)
        try:
            os.remove(self._path(key))
        except (OSError, KeyError):
            pass
        return value

    def items(self):
        try:
            names = sorted(os.listdir(self._dir))
        except OSError:
            return
        for name in names:
            if not name.endswith(".json"):
                continue
            key = name[: -len(".json")]
            value = self.get(key)
            if value is not None:
                yield key, value

    # dict 자리에 그대로 들어가므로 나머지 dict 인터페이스도 맞춰 둔다.
    def keys(self):
        return [key for key, _ in self.items()]

    def __iter__(self):
        return iter(self.keys())

    def clear(self) -> None:
        for key in self.keys():
            self.pop(key, None)

    def update(self, other) -> None:
        for key, value in dict(other).items():
            self[key] = value


_masked_files = _SharedDict(
    "infoguard_masked",
    lambda raw: _MaskedFile(**raw),
    lambda entry: asdict(entry),
)
_batches = _SharedDict("infoguard_batches", list, list)


def _sweep_expired() -> None:
    """TTL이 지난 사본을 지운다. 별도 스케줄러 없이 요청이 올 때마다 훑는다."""
    deadline = time.time() - MASKED_FILE_TTL_SECONDS
    for file_id, entry in list(_masked_files.items()):
        if entry.created_at < deadline:
            _remove_quietly(entry.path)
            _masked_files.pop(file_id, None)
    for batch_id, file_ids in list(_batches.items()):
        if not any(fid in _masked_files for fid in file_ids):
            _batches.pop(batch_id, None)


# ---------------------------------------------------------------------------
# 비동기 검사 작업
# ---------------------------------------------------------------------------
#
# 대용량 로그·CSV(수만 줄)는 NER이 줄마다 돌아 동기 요청 하나로 처리하면 수 분이
# 걸린다(실측 2026-09-20: 25,146줄짜리 5MB 로그가 배치 크기를 키워도 CPU 연산량
# 자체가 병목이라 약 17분). 프런트엔드 fetch 타임아웃(180초)과 Railway 프록시
# 타임아웃(5분) 둘 다 그보다 짧아 동기 응답으로는 절대 끝을 볼 수 없다. 요청을
# 즉시 접수만 하고(job_id 발급) 실제 검사는 백그라운드에서 돌리며, 화면은
# job_id로 상태를 주기적으로 물어본다(GET /scan/async/{job_id}).
#
# 상태를 프로세스 메모리(dict)에 두면 안 된다 — Dockerfile이 uvicorn을
# --workers 4로 띄우므로 워커마다 별도 프로세스·별도 메모리다. 접수 요청과
# 상태 조회 요청이 로드밸런서를 통해 서로 다른 워커로 가면(실측 2026-09-20,
# 배포 직후: 제출은 성공했는데 곧바로 상태 조회가 "작업을 찾을 수 없습니다"
# 404) 방금 만든 job을 다른 워커는 전혀 모른다. 컨테이너 안 모든 워커가
# 공유하는 디스크에 파일로 써서 이 문제를 피한다.

_SCAN_JOB_DIR = os.path.join(tempfile.gettempdir(), "infoguard_scan_jobs")


_SCAN_JOB_ID_PATTERN = _ID_PATTERN


def _scan_job_path(job_id: str) -> str:
    # job_id는 GET /scan/async/{job_id}로 사용자 입력이 그대로 들어온다("../../etc/passwd" 등).
    # uuid4().hex 모양이 아니면 경로를 조립하지 않는다.
    if not _SCAN_JOB_ID_PATTERN.match(job_id):
        raise ValueError("invalid job id")
    return os.path.join(_SCAN_JOB_DIR, f"{job_id}.json")


def _write_scan_job(job_id: str, status: str, result: dict | None = None, detail: str | None = None) -> None:
    payload = {"status": status, "created_at": time.time(), "result": result, "detail": detail}
    _atomic_write_json(_scan_job_path(job_id), payload)


def _read_scan_job(job_id: str) -> dict | None:
    try:
        path = _scan_job_path(job_id)
    except ValueError:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def _sweep_expired_jobs() -> None:
    deadline = time.time() - SCAN_JOB_TTL_SECONDS
    if not os.path.isdir(_SCAN_JOB_DIR):
        return
    for name in os.listdir(_SCAN_JOB_DIR):
        path = os.path.join(_SCAN_JOB_DIR, name)
        try:
            if os.path.getmtime(path) < deadline:
                _remove_quietly(path)
        except OSError:
            pass


def _sweep_orphan_dirs() -> int:
    """이전 프로세스가 남긴 사본 폴더를 지운다. 지운 개수를 돌려준다.

    TTL이 지난 것만 건드린다. 같은 머신에서 다른 인스턴스가 돌고 있을 수 있는데,
    그쪽이 방금 만든 사본을 지우면 사용자가 다운로드 버튼을 눌렀을 때 404가 난다.
    """
    removed = 0
    deadline = time.time() - MASKED_FILE_TTL_SECONDS
    root = tempfile.gettempdir()
    try:
        names = os.listdir(root)
    except OSError:
        return 0
    for name in names:
        if not name.startswith(MASKED_DIR_PREFIX):
            continue
        target = os.path.join(root, name)
        try:
            if os.path.getmtime(target) >= deadline:
                continue
            shutil.rmtree(target, ignore_errors=True)
            removed += 1
        except OSError:
            continue
    return removed


def _remove_quietly(path: str) -> None:
    """지우다 실패해도 요청을 깨뜨리지 않는다. 임시 파일 정리는 부가 작업이다."""
    try:
        os.remove(path)
    except OSError:
        pass
    parent = os.path.dirname(path)
    if parent.startswith(tempfile.gettempdir()):
        try:
            os.rmdir(parent)
        except OSError:
            pass


def _register_masked(result: schema.ScanResult, batch_id: str | None = None) -> None:
    """ScanResult.masked_path를 다운로드 가능한 file_id로 바꿔 등록한다."""
    if not result.masked_path or not os.path.exists(result.masked_path):
        return
    file_id = uuid.uuid4().hex
    _masked_files[file_id] = _MaskedFile(
        path=result.masked_path,
        download_name=os.path.basename(result.masked_path),
        created_at=time.time(),
        batch_id=batch_id,
    )
    result.file_id = file_id


def _batch_of(file_id: str | None) -> str | None:
    """그 사본이 속한 배치. 부분 마스킹 사본은 대체한 사본의 배치를 그대로 물려받는다."""
    entry = _masked_files.get(file_id) if file_id else None
    return entry.batch_id if entry else None


# ---------------------------------------------------------------------------
# 업로드 처리
# ---------------------------------------------------------------------------


def _safe_basename(name: str | None) -> str:
    """업로드된 파일명에서 경로 성분을 떼어낸다.

    클라이언트는 "../../etc/passwd"나 "C:\\Windows\\x"도 보낼 수 있다. 파일명을
    그대로 경로에 이어 붙이면 엉뚱한 곳에 쓰게 된다.
    """
    base = os.path.basename((name or "upload").replace("\\", "/"))
    return base or "upload"


async def _spool_upload(upload: UploadFile, dest_dir: str) -> str:
    """업로드를 임시 파일로 받는다. 상한을 넘으면 받다 말고 끊는다.

    파일마다 고유한 하위 폴더에 쓴다. 안 그러면 한 배치 안에 같은 이름의 파일이
    두 개 있을 때(실무에서 흔한 "invoice.pdf" 두 개 업로드 등) 같은 dest_dir
    경로에 겹쳐 써서, 나중 파일이 먼저 쓴 파일을 덮어쓴다 — 첫 번째 파일은
    검사되지도 않은 채 조용히 사라지고, 대신 두 번째 파일 내용이 두 번
    스캔된 것처럼 결과가 나온다(실측: 2026-09-16).
    """
    unique_dir = tempfile.mkdtemp(dir=dest_dir)
    path = os.path.join(unique_dir, _safe_basename(upload.filename))
    written = 0
    with open(path, "wb") as out:
        while chunk := await upload.read(1024 * 1024):
            written += len(chunk)
            if written > MAX_UPLOAD_BYTES:
                out.close()
                _remove_quietly(path)
                raise HTTPException(
                    status_code=413,
                    detail=f"파일이 너무 큽니다 (최대 {MAX_UPLOAD_BYTES // (1024 * 1024)}MB)",
                )
            out.write(chunk)
    return path


# ---------------------------------------------------------------------------
# 엔드포인트
# ---------------------------------------------------------------------------


class ScanTextRequest(BaseModel):
    text: str = Field(min_length=1, max_length=MAX_TEXT_LENGTH)


def _parse_masking_policy(raw: str | None) -> dict:
    """Parse the optional multipart JSON field without echoing it in errors."""
    if raw is None or not raw.strip():
        return mask_policy.normalize_policy(None)
    try:
        value = json.loads(raw)
        return mask_policy.normalize_policy(value)
    except (json.JSONDecodeError, ValueError) as exc:
        # normalize_policy errors contain only field/type names, never document content.
        raise HTTPException(status_code=422, detail=str(exc)) from None


def _parse_masking_selection(raw: str) -> list[dict]:
    """Parse the per-finding choices returned by the result screen."""
    try:
        value = json.loads(raw)
        return mask_policy.normalize_selection(value)
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None


@app.get("/health")
def health() -> dict:
    """배포 후 살아있는지 확인. 링크가 10/5까지 살아 있어야 해서 모니터링이 이걸 찍는다.

    훈련 모드가 안 붙었으면 그 사실을 같이 알린다. 조용히 사라지면 C가 왜 자기
    엔드포인트가 404인지 알 길이 없다.
    """
    body = {"status": "ok", "schema_version": schema.SCHEMA_VERSION}
    revision = os.getenv("RAILWAY_GIT_COMMIT_SHA", "").strip()
    if revision:
        body["revision"] = revision[:8]
    body["training_mode"] = "on" if training_router is not None else "off"
    if _TRAINING_ROUTER_ERROR:
        body["training_mode_error"] = _TRAINING_ROUTER_ERROR
    body["db_mode"] = "on" if SessionLocal is not None else "off"
    if _DB_ERROR:
        body["db_mode_error"] = _DB_ERROR

    # 이미지 OCR 엔진(EasyOCR) 상태를 여기 노출한다. 2026-09-18에 Tesseract에서
    # 갈아탔다 — 배포/로컬 Tesseract 버전 차이로 같은 이미지를 다르게 읽는
    # 사고까지 있었던 것과 달리, EasyOCR은 pip 패키지 버전이 uv.lock으로
    # 고정되므로 그런 사고가 구조적으로 안 생긴다. `easyocr_ready`는 모델을
    # 이미 메모리에 올렸는지(첫 이미지 검사 요청 전까지는 False가 정상)를 보여준다
    # — 모델 자체를 여기서 새로 불러오면 모니터링이 이 엔드포인트를 두드릴 때마다
    # 무거워지므로, 이미 있으면 상태만 보고하고 없으면 불러오지 않는다.
    try:
        from backend.scanner.detectors import text_ocr

        body["easyocr_ready"] = text_ocr._reader is not None
    except Exception as exc:  # noqa: BLE001 — /health는 이 정보 없이도 응답해야 한다
        body["easyocr_error"] = type(exc).__name__
    return body


@app.get("/masking/options")
def masking_options() -> dict:
    """화면이 마스킹 방식 선택 UI를 만들 때 사용하는 단일 기준표."""
    return mask_policy.options_payload()


async def _spool_batch(files: list[UploadFile], upload_dir: str) -> tuple[list[str], dict[str, str], list[str], int]:
    """업로드 파일들을 임시 폴더에 받고, 이후 단계에 필요한 정보를 모아 돌려준다.

    (경로 목록, 경로->원래 파일명, 확장자 목록, 총 바이트) — scan_upload와
    scan_upload_async가 같은 스풀링·이름 복원 로직을 쓴다.
    """
    paths = [await _spool_upload(f, upload_dir) for f in files]
    input_bytes = sum(os.path.getsize(path) for path in paths)
    # scan_file은 자기가 받은 경로를 filename에 넣는데, 여기서 넘긴 것은 업로드
    # 임시 경로다(…/Temp/infoguard_upload_xxxx/연락처.pdf). 그대로 내보내면
    # **서버 디렉터리 구조가 응답에 실려 나가고**, 화면에는 파일명 대신 그 경로가
    # 뜬다. 사용자가 올린 이름으로 돌려놓는다 — 경로 성분은 _safe_basename이
    # 이미 떼어냈다(클라이언트가 "../../etc/passwd"를 보낼 수 있다).
    display_name = {path: _safe_basename(f.filename) for path, f in zip(paths, files)}
    file_types = sorted({os.path.splitext(_safe_basename(f.filename))[1].lower() or "unknown" for f in files})
    return paths, display_name, file_types, input_bytes


def _run_scan_batch(
    paths: list[str],
    display_name: dict[str, str],
    file_types: list[str],
    input_bytes: int,
    selected_policy: dict,
    create_masked_copy: bool,
    started: float,
    file_count: int,
) -> dict:
    """스캔을 실행하고 파일명 복원·마스킹 사본 등록·로그까지 끝낸 응답 본문을 만든다.

    동기 함수다 — /scan은 run_in_threadpool로, /scan/async는 백그라운드 스레드에서
    부른다. 둘 다 CPU 동기 작업이라 이벤트 루프에서 직접 돌리면 안 된다.
    """
    batch = scan.scan_files(paths, masking_policy=selected_policy, create_masked_copy=create_masked_copy)

    # 순서로 맞추지 않고 경로를 키로 쓴다. 결과 목록의 순서가 입력 순서와
    # 달라져도(정렬·건너뜀) 엉뚱한 파일에 이름이 붙지 않는다.
    for result in batch.results:
        result.filename = display_name.get(result.filename, os.path.basename(result.filename))

    batch.batch_id = uuid.uuid4().hex
    for result in batch.results:
        _register_masked(result, batch_id=batch.batch_id)
    _batches[batch.batch_id] = [r.file_id for r in batch.results if r.file_id]
    _persist_scan_results(batch.results)

    finding_counts = Counter(
        finding.type for result in batch.results for finding in result.findings
    )
    risk_levels = Counter(result.level for result in batch.results)
    log_event(
        logger,
        logging.INFO,
        "scan.files.completed",
        duration_ms=round((time.perf_counter() - started) * 1000, 1),
        file_count=file_count,
        file_types=file_types,
        input_bytes=input_bytes,
        masked_file_count=sum(bool(result.file_id) for result in batch.results),
        total_findings=sum(finding_counts.values()),
        filtered_out=sum(len(result.filtered_out) for result in batch.results),
        finding_counts=dict(sorted(finding_counts.items())),
        risk_levels=dict(sorted(risk_levels.items())),
    )

    body = batch.to_dict()
    body["masking_policy"] = selected_policy
    body["masked_copy_created"] = create_masked_copy
    return body


@app.post("/scan")
async def scan_upload(
    files: list[UploadFile],
    masking_policy_json: str | None = Form('{"default":"full","rules":{}}', alias="masking_policy"),
    create_masked_copy: bool = Form(default=True),
) -> dict:
    """파일 여러 개를 검사해 위험도 순으로 돌려준다.

    업로드 원본은 이 함수를 벗어나기 전에 지운다. 마스킹 사본만 file_id로 남는다.
    대용량 로그·CSV처럼 오래 걸릴 수 있는 요청은 /scan/async를 쓴다.
    """
    if not files:
        raise HTTPException(status_code=400, detail="파일이 없습니다")
    if len(files) > MAX_FILES_PER_REQUEST:
        raise HTTPException(
            status_code=413, detail=f"한 번에 {MAX_FILES_PER_REQUEST}개까지 올릴 수 있습니다"
        )

    selected_policy = _parse_masking_policy(masking_policy_json)
    started = time.perf_counter()
    _sweep_expired()
    upload_dir = tempfile.mkdtemp(prefix="infoguard_upload_")
    try:
        paths, display_name, file_types, input_bytes = await _spool_batch(files, upload_dir)
        # 파일 파싱과 ML 추론은 CPU 동기 작업이다. async 엔드포인트에서 직접
        # 실행하면 긴 XLSX 한 건이 이벤트 루프를 막아 /health까지 응답하지 못한다.
        body = await run_in_threadpool(
            _run_scan_batch,
            paths,
            display_name,
            file_types,
            input_bytes,
            selected_policy,
            create_masked_copy,
            started,
            len(files),
        )
    finally:
        # 제품 원칙: 업로드 원본은 저장하지 않는다. 스캔이 실패해도 지운다.
        shutil.rmtree(upload_dir, ignore_errors=True)

    return body


@app.post("/scan/async", status_code=202)
async def scan_upload_async(
    files: list[UploadFile],
    masking_policy_json: str | None = Form('{"default":"full","rules":{}}', alias="masking_policy"),
    create_masked_copy: bool = Form(default=True),
) -> dict:
    """/scan과 같은 검사를 백그라운드에서 돌린다. 즉시 job_id만 돌려준다.

    대용량 로그·CSV(수만 줄)는 NER이 줄마다 돌아 몇 분씩 걸릴 수 있어(실측
    2026-09-20: 5MB·25,146줄 로그 약 17분), 동기 응답으로는 프런트엔드 fetch
    타임아웃(180초)과 Railway 프록시 타임아웃(5분)을 넘긴다. 화면은 이 job_id로
    GET /scan/async/{job_id}를 주기적으로 물어 진행 상태를 확인한다.
    """
    if not files:
        raise HTTPException(status_code=400, detail="파일이 없습니다")
    if len(files) > MAX_FILES_PER_REQUEST:
        raise HTTPException(
            status_code=413, detail=f"한 번에 {MAX_FILES_PER_REQUEST}개까지 올릴 수 있습니다"
        )

    selected_policy = _parse_masking_policy(masking_policy_json)
    started = time.perf_counter()
    _sweep_expired()
    _sweep_expired_jobs()
    upload_dir = tempfile.mkdtemp(prefix="infoguard_upload_")
    try:
        paths, display_name, file_types, input_bytes = await _spool_batch(files, upload_dir)
    except Exception:
        shutil.rmtree(upload_dir, ignore_errors=True)
        raise

    job_id = uuid.uuid4().hex
    _write_scan_job(job_id, "running")
    file_count = len(files)

    def _worker() -> None:
        try:
            body = _run_scan_batch(
                paths, display_name, file_types, input_bytes,
                selected_policy, create_masked_copy, started, file_count,
            )
            _write_scan_job(job_id, "done", result=body)
        except Exception:  # noqa: BLE001 — 백그라운드 스레드라 여기서 잡지 않으면 조용히 사라진다
            _write_scan_job(job_id, "error", detail="검사 중 오류가 발생했습니다")
        finally:
            # 제품 원칙: 업로드 원본은 저장하지 않는다. 스캔이 실패해도 지운다.
            shutil.rmtree(upload_dir, ignore_errors=True)

    threading.Thread(target=_worker, daemon=True).start()
    return {"job_id": job_id, "status": "running"}


@app.get("/scan/async/{job_id}")
def scan_job_status(job_id: str) -> dict:
    """진행 상태를 돌려준다. done이면 /scan과 같은 모양의 결과가 result에 들어 있다."""
    job = _read_scan_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="검사 작업을 찾을 수 없습니다")
    body: dict = {"status": job["status"]}
    if job["status"] == "done":
        body["result"] = job["result"]
    elif job["status"] == "error":
        body["detail"] = job["detail"]
    return body


@app.post("/mask")
async def mask_selected_findings(
    file: UploadFile,
    masking_selection_json: str = Form(alias="masking_selection"),
    replaces: str | None = Form(default=None),
) -> dict:
    """Re-scan one file and create a copy from the user's finding selections.

    The browser sends the original File object again. The server never keeps an
    original between the preview and masking requests.
    """
    selections = _parse_masking_selection(masking_selection_json)
    started = time.perf_counter()
    _sweep_expired()
    upload_dir = tempfile.mkdtemp(prefix="infoguard_upload_")
    try:
        path = await _spool_upload(file, upload_dir)
        input_bytes = os.path.getsize(path)
        try:
            result = await run_in_threadpool(
                scan.scan_file,
                path,
                masking_selection=selections,
                create_masked_copy=True,
            )
        except ValueError as exc:
            # The file changed, or the UI sent selections from another result.
            raise HTTPException(status_code=409, detail=str(exc)) from None
    finally:
        shutil.rmtree(upload_dir, ignore_errors=True)

    if result.error:
        raise HTTPException(status_code=422, detail="파일을 다시 검사하지 못했습니다")
    if not result.masked_path or not os.path.exists(result.masked_path):
        raise HTTPException(status_code=500, detail="마스킹 사본을 만들지 못했습니다")

    # 새 사본은 대체한 사본과 같은 배치에 속한다. 배치 목록 자체는 건드리지 않는다.
    _register_masked(result, batch_id=_batch_of(replaces))
    log_event(
        logger,
        logging.INFO,
        "mask.file.completed",
        duration_ms=round((time.perf_counter() - started) * 1000, 1),
        file_count=1,
        file_types=[result.file_type or "unknown"],
        input_bytes=input_bytes,
        masked_file_count=1,
        total_findings=len(selections),
        finding_counts=dict(sorted(Counter(row["type"] for row in selections).items())),
    )
    return _selected_copy_response(result, _safe_basename(result.filename), selections)


def _selected_copy_response(result: schema.ScanResult, filename: str, selections: list[dict]) -> dict:
    """/mask와 /samples/mask가 같은 모양으로 돌려주는 응답.

    masked_text는 선택을 적용해 다시 만든 텍스트 사본이다(scan.scan_file이 masking_selection으로
    채운다). 부분 마스킹 모양("김**")은 서버 규칙(policy.py)이 정하므로, 화면은 규칙을 복사하지
    않고 이 값으로 미리보기를 보여준다.
    """
    return {
        "file_id": result.file_id,
        "filename": filename,
        "file_type": result.file_type,
        "selected_findings": len(selections),
        "download_url": f"/download/{result.file_id}",
        "masked_text": result.masked_text,
    }


@app.post("/scan/text")
def scan_one_text(request: ScanTextRequest) -> dict:
    """문장 하나를 검사한다. 훈련 모드(C)가 답장을 보내기 전에 부른다.

    파일이 아니므로 사본도 file_id도 없다. masked_text는 응답에 그대로 들어간다.
    """
    started = time.perf_counter()
    result = scan.scan_text(request.text)
    _persist_scan_results([result])
    log_event(
        logger,
        logging.INFO,
        "scan.text.completed",
        duration_ms=round((time.perf_counter() - started) * 1000, 1),
        input_bytes=len(request.text.encode("utf-8")),
        total_findings=len(result.findings),
        filtered_out=len(result.filtered_out),
        finding_counts=dict(sorted(Counter(f.type for f in result.findings).items())),
        risk_levels={result.level: 1},
    )
    return result.to_dict()


class HiddenCommandStatusUpdate(BaseModel):
    status: Literal["확인필요", "제거함", "무시함"]


@app.patch("/scan-results/{scan_result_id}/hidden-commands/{finding_ref}")
def update_hidden_command_status(
    scan_result_id: int,
    finding_ref: str,
    request: HiddenCommandStatusUpdate,
) -> dict:
    """화면에서 숨은 명령을 제거/무시했을 때 DB 기록을 갱신한다.

    scan_result_id는 ScanResult.db_id(저장이 성공했을 때만 채워진다), finding_ref는
    이미 응답에 있는 Finding.id("f_003" 같은 값)를 그대로 쓴다 — 화면이 새로 알아야
    할 값은 scan_result_id 하나뿐이다.

    이 기록은 화면 표시를 위한 보조 데이터다. 저장이 꺼져 있거나 실패해도 사용자가
    이미 마스킹/무시 조치를 끝낸 뒤 보내는 후속 기록이므로, 화면은 이 요청이 실패해도
    이미 끝난 작업을 무르지 않는다.
    """
    if SessionLocal is None or FindingRow is None:
        raise HTTPException(status_code=404, detail="저장 기능이 꺼져 있어 상태를 기록할 수 없습니다")

    db = SessionLocal()
    try:
        finding_row = (
            db.query(FindingRow)
            .filter(
                FindingRow.scan_result_id == scan_result_id,
                FindingRow.finding_ref == finding_ref,
            )
            .first()
        )
        if finding_row is None or finding_row.hidden_command is None:
            raise HTTPException(status_code=404, detail="숨은 명령 기록을 찾을 수 없습니다")

        finding_row.hidden_command.status = request.status
        db.commit()
        return {
            "scan_result_id": scan_result_id,
            "finding_ref": finding_ref,
            "status": request.status,
        }
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        log_event(
            logger,
            logging.WARNING,
            "hidden_command.update.failed",
            error_code=type(exc).__name__,
        )
        raise HTTPException(status_code=500, detail="상태 갱신에 실패했습니다") from exc
    finally:
        db.close()


@app.get("/download/all")
def download_all(batch_id: str, files: str | None = None) -> FileResponse:
    """배치의 사본을 .zip으로 내려준다. files를 주면 그중 고른 것만 묶는다.

    zip은 요청할 때 만들고 응답을 보낸 뒤 지운다(BackgroundTask). 미리 만들어 두면
    내려받지 않은 zip이 디스크에 남는다.

    files는 배치 안으로만 좁히는 거르개다 — 배치에 없는 id는 조용히 버린다. 이렇게 해야
    "이 배치의 사본만 내려간다"는 성질이 유지된다. id 목록만 받고 배치를 안 보면 다른
    배치의 사본을 섞어 달라고 요청할 수 있다.
    """
    _sweep_expired()
    file_ids = _batches.get(batch_id)
    if not file_ids:
        raise HTTPException(status_code=404, detail="배치가 없거나 보관 기간이 지났습니다")

    if files is not None:
        # 배치 목록(file_ids)이 아니라 사본에 붙은 배치 표시로 확인한다. 부분 마스킹 사본은
        # 검사 뒤에 만들어져 목록에는 없지만 같은 배치의 것이다. 중복 id는 순서를 유지하며
        # 한 번만 넣는다.
        file_ids = list(dict.fromkeys(fid for fid in files.split(",") if fid))
        if not file_ids:
            raise HTTPException(status_code=404, detail="내려받을 사본을 선택해 주세요")

    # 일부만 조용히 zip에 넣지 않는다. 선택한 사본 중 하나라도 만료됐거나 다른 배치의
    # 것이면 사용자는 '전체를 받았다'고 오해할 수 있으므로, 전부 실패시키고 다시 검사를
    # 안내한다.
    unavailable = [
        fid
        for fid in file_ids
        if _batch_of(fid) != batch_id
        or fid not in _masked_files
        or not os.path.exists(_masked_files[fid].path)
    ]
    if unavailable:
        raise HTTPException(
            status_code=404,
            detail="선택한 사본 중 일부가 없거나 보관 기간이 지났습니다. 다시 검사해 주세요",
        )

    entries = [_masked_files[fid] for fid in file_ids]

    zip_dir = tempfile.mkdtemp(prefix="infoguard_zip_")
    zip_path = os.path.join(zip_dir, "docxray_masked.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
        used: set[str] = set()
        for entry in entries:
            if not os.path.exists(entry.path):
                continue
            # 같은 이름이 둘 이상이면 zip 안에서 덮어써진다. 뒤에 번호를 붙인다.
            name = entry.download_name
            stem, ext = os.path.splitext(name)
            counter = 1
            while name in used:
                name = f"{stem}_{counter}{ext}"
                counter += 1
            used.add(name)
            archive.write(entry.path, arcname=name)

    log_event(
        logger,
        logging.INFO,
        "download.batch.ready",
        file_count=len(entries),
    )

    return FileResponse(
        zip_path,
        filename="docxray_masked.zip",
        media_type="application/zip",
        background=BackgroundTask(shutil.rmtree, zip_dir, ignore_errors=True),
    )


# /download/all 아래에 둔다. FastAPI는 선언 순서대로 경로를 맞추므로, 이걸 위에
# 두면 /download/all 요청이 file_id="all"로 잡혀서 항상 404가 난다(실제로 겪었다).
@app.get("/download/{file_id}")
def download_one(file_id: str) -> FileResponse:
    """마스킹 사본 하나를 내려준다. file_id는 /scan 응답의 그 값이다."""
    _sweep_expired()
    entry = _masked_files.get(file_id)
    if entry is None or not os.path.exists(entry.path):
        raise HTTPException(status_code=404, detail="사본이 없거나 보관 기간이 지났습니다")
    log_event(
        logger,
        logging.INFO,
        "download.file.ready",
        file_count=1,
        file_types=[os.path.splitext(entry.download_name)[1].lower() or "unknown"],
    )
    return FileResponse(
        entry.path, filename=entry.download_name, media_type="application/octet-stream"
    )


# ---------------------------------------------------------------------------
# 심사위원용 샘플
# ---------------------------------------------------------------------------
#
# 첫 화면에서 심사위원이 누르는 버튼이다("샘플로 체험하기"). 예선 배점의 투표 20%가
# 여기서 갈리므로 **절대 느리면 안 된다.** 파일을 매번 다시 스캔하면 NER 모델 로딩과
# CNN 추론까지 걸려서 첫 클릭이 수십 초가 된다. 그래서 한 번 계산해 캐시에 둔다.

SAMPLE_DIR = os.path.join("sample_data", "demo")
_sample_cache: dict | None = None
_sample_batch: schema.ScanBatch | None = None


def _sample_paths() -> list[str]:
    """데모 파일 목록. parse가 읽을 수 있는 확장자만 고른다 —
    sample_data 아래에는 분류기 학습용 JSON도 있어서 그대로 넘기면 ParseError가 난다."""
    if not os.path.isdir(SAMPLE_DIR):
        return []
    readable = set(scan._FILE_TYPE_BY_EXTENSION)
    return sorted(
        os.path.join(SAMPLE_DIR, name)
        for name in os.listdir(SAMPLE_DIR)
        # "~$"로 시작하는 파일은 Word가 문서를 열어 둘 때 만드는 잠금 파일이다.
        # 확장자가 .docx라 걸러내지 않으면 깨진 문서가 샘플로 한 건 더 잡힌다
        # (sample_data/demo/~$숨은명령.docx가 실수로 커밋되어 있다).
        if os.path.splitext(name)[1].lower() in readable and not name.startswith("~$")
    )


def _sample_copies_alive(cached: dict) -> bool:
    """캐시된 샘플 결과의 마스킹 사본이 아직 내려받을 수 있는 상태인지.

    결과(JSON)는 캐시에 계속 남지만 사본 파일은 MASKED_FILE_TTL_SECONDS가 지나면
    _sweep_expired가 지운다. 확인 없이 캐시를 돌려주면 화면의 다운로드 버튼이 전부
    404가 된다(실측 2026-09-14: 서버를 띄우고 30분이 지난 뒤 /download/{file_id}와
    /download/all 모두 "보관 기간이 지났습니다").
    """
    file_ids = _batches.get(cached.get("batch_id", ""))
    return bool(file_ids) and all(fid in _masked_files for fid in file_ids)


@app.get("/samples/list")
def sample_list() -> dict:
    """데모 파일 목록만 돌려준다. **검사는 하지 않는다.**

    /samples는 첫 호출에 모델을 올리고 파일을 전부 검사하느라 수십 초가 걸린다.
    첫 화면이 "고를 목록"을 그리자고 그것을 부를 수는 없어서 이름만 따로 내보낸다.
    """
    return {
        "samples": [
            {
                "filename": os.path.basename(path),
                # _sample_paths()가 이미 쓰는 표를 그대로 본다. 형식 이름을 여기서 새로 짓지 않는다.
                "file_type": scan._FILE_TYPE_BY_EXTENSION.get(os.path.splitext(path)[1].lower(), ""),
                "size_bytes": os.path.getsize(path),
            }
            for path in _sample_paths()
        ]
    }


@app.get("/samples/original/{filename}")
def sample_original(filename: str) -> FileResponse:
    """합성 샘플의 원본을 상세 미리보기 전용으로 돌려준다.

    실제 업로드 문서는 서버에서 즉시 삭제하지만, 이 경로는 저장소에 함께 배포되는
    합성 데모 파일만 _sample_paths() 허용 목록에서 찾아 전달한다. 사용자 입력을
    경로로 조합하지 않아 디렉터리 이탈은 불가능하다.
    """
    path = {os.path.basename(item): item for item in _sample_paths()}.get(filename)
    if path is None:
        raise HTTPException(status_code=404, detail="샘플 문서를 찾을 수 없습니다")
    return FileResponse(
        path,
        media_type="application/octet-stream",
        headers={"Cache-Control": "no-store"},
    )


def _sample_subset(names: str | None) -> dict:
    """고른 샘플만 남긴 결과. 고르지 않았거나 하나도 못 찾으면 전체를 그대로 돌려준다.

    검사와 캐시는 **늘 전체로** 한다. 파일이 넷뿐이라 고른 것만 따로 검사하면 조합마다
    캐시가 따로 생기고, 심사위원이 처음 누르는 클릭이 그만큼 느려진다.

    batch_id를 새로 만드는 이유: "사본 전체 받기(.zip)"는 batch_id로 묶인 파일을 담는다.
    전체 batch_id를 그대로 주면 두 개만 골랐는데 zip에는 네 개가 들어간다.

    실측 버그(2026-09-19): 새 batch_id를 `_batches`(배치 -> 파일 목록)에는 등록해
    놓고, 정작 각 파일의 `_masked_files[fid].batch_id`(파일 -> 배치 역방향 조회,
    `_batch_of`가 쓰는 값)는 예전 배치를 그대로 가리키고 있었다. `/download/all`이
    파일마다 `_batch_of(fid) != batch_id`로 소속을 확인하는데, 골라 받은 파일은
    전부 이 새 batch_id와 맞지 않아 하나도 못 넘어가서 zip이 매번 404였다("선택
    파일 다운받기"는 파일 하나씩 `/download/{id}`만 확인해서 같은 상황에서도 잘
    됐다 — 증상이 갈렸던 이유). 골라 받은 파일들의 등록도 이 새 batch_id로
    같이 옮겨야 한다.
    """
    if not names or _sample_batch is None:
        return _sample_cache
    wanted = {name for name in names.split(",") if name}
    picked = [r for r in _sample_batch.results if r.filename in wanted]
    if not picked:
        return _sample_cache
    subset = schema.ScanBatch(results=picked, batch_id=uuid.uuid4().hex)
    file_ids = [r.file_id for r in picked if r.file_id]
    _batches[subset.batch_id] = file_ids
    for file_id in file_ids:
        entry = _masked_files.get(file_id)
        if entry is not None:
            entry.batch_id = subset.batch_id
            # 레지스트리는 디스크에 있다. 꺼내 온 객체를 고치는 것만으로는 남지 않는다.
            _masked_files[file_id] = entry
    return subset.to_dict()


@app.get("/samples")
def samples(files: str | None = None) -> dict:
    """샘플을 미리 검사한 결과. 두 번째 호출부터는 캐시에서 즉시 나간다.

    캐시한 결과의 사본이 보관 기간을 넘겨 지워졌으면 다시 검사해서 새 사본을 만든다.
    그때는 모델이 이미 올라와 있어서 첫 호출만큼 오래 걸리지 않는다.
    """
    global _sample_cache, _sample_batch
    if _sample_cache is not None:
        log_event(logger, logging.INFO, "samples.returned", cache_hit=True)
    _sweep_expired()
    if _sample_cache is not None and _sample_copies_alive(_sample_cache):
        return _sample_subset(files)

    paths = _sample_paths()
    if not paths:
        # 데모 파일은 A(sample_data/ 담당)가 넣는다. 아직 없으면 빈 목록을
        # 돌려주되, 화면이 "샘플 없음"과 "서버 오류"를 구분할 수 있게 알려준다.
        return {
            "schema_version": schema.SCHEMA_VERSION,
            "results": [],
            "total_files": 0,
            "total_findings": 0,
            "note": f"데모 샘플이 아직 없습니다 ({SAMPLE_DIR})",
        }

    batch = scan.scan_files(paths)
    # /scan과 같은 이유로 경로가 아니라 파일명만 내보낸다.
    for result in batch.results:
        result.filename = os.path.basename(result.filename)
    batch.batch_id = uuid.uuid4().hex
    for result in batch.results:
        _register_masked(result, batch_id=batch.batch_id)
    _batches[batch.batch_id] = [r.file_id for r in batch.results if r.file_id]

    _sample_cache = batch.to_dict()
    _sample_batch = batch          # 고른 것만 추릴 때 ScanBatch의 정렬·집계를 그대로 쓴다
    log_event(
        logger,
        logging.INFO,
        "samples.returned",
        cache_hit=False,
        file_count=len(batch.results),
        total_findings=sum(len(result.findings) for result in batch.results),
    )
    return _sample_subset(files)


class SampleMaskRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    selections: list[dict] = Field(min_length=1)
    # 화면이 들고 있던 이전 사본의 file_id. 배치 .zip에서 이 자리를 새 사본으로 바꾼다.
    replaces: str | None = Field(default=None, max_length=64)


@app.post("/samples/mask")
def mask_selected_sample(request: SampleMaskRequest) -> dict:
    """샘플 문서에서 화면이 고른 항목만 가린 사본을 만든다.

    /mask는 브라우저가 원본 File을 다시 보내는 방식인데, "샘플로 체험하기"는 브라우저에 원본이
    없다. 샘플은 저장소(sample_data/demo)에 있는 가상 데이터라 서버에 있는 파일을 다시 검사한다.

    경로를 사용자 입력으로 만들지 않는다 — filename은 _sample_paths() 목록의 파일 이름과
    정확히 같을 때만 받는다. "../backend/main.py" 같은 값은 목록에 없으므로 404가 된다.
    """
    try:
        selections = mask_policy.normalize_selection({"selections": request.selections})
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None

    path = {os.path.basename(p): p for p in _sample_paths()}.get(request.filename)
    if path is None:
        raise HTTPException(status_code=404, detail="샘플 문서를 찾을 수 없습니다")

    started = time.perf_counter()
    _sweep_expired()
    try:
        result = scan.scan_file(path, masking_selection=selections, create_masked_copy=True)
    except ValueError as exc:
        # 화면이 다른 결과의 선택을 보냈거나, 샘플 파일이 바뀌어 재검사 결과가 달라진 경우.
        raise HTTPException(status_code=409, detail=str(exc)) from None

    if result.error:
        raise HTTPException(status_code=422, detail="샘플 문서를 다시 검사하지 못했습니다")
    if not result.masked_path or not os.path.exists(result.masked_path):
        raise HTTPException(status_code=500, detail="마스킹 사본을 만들지 못했습니다")

    _register_masked(result, batch_id=_batch_of(request.replaces))
    log_event(
        logger,
        logging.INFO,
        "samples.mask.completed",
        duration_ms=round((time.perf_counter() - started) * 1000, 1),
        file_count=1,
        file_types=[result.file_type or "unknown"],
        masked_file_count=1,
        total_findings=len(selections),
        finding_counts=dict(sorted(Counter(row["type"] for row in selections).items())),
    )
    return _selected_copy_response(result, request.filename, selections)
