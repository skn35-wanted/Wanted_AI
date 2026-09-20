"""오래 방치된 TiDB 트랜잭션을 강제로 끊는다.

실측(2026-09-20): PR #60 머지 충돌로 Railway 배포가 502 크래시 루프를 도는
동안, 그 짧은 창에서도 실제 요청을 받아 DB 트랜잭션을 연 워커가 재시작되며
그 트랜잭션이 TiDB 쪽에는 커밋도 롤백도 안 된 채(연결만 뚝 끊겨서) 그대로
남았다. TiDB는 그 연결이 죽었다는 걸 스스로 알아채지 못해(서버 쪽
wait_timeout이 기본값으로 아주 길다) 트랜잭션이 15분 넘게 "Sleep, in
transaction" 상태로 방치됐고, 그게 잡은 락 때문에 training_progress에
새로 INSERT하는 모든 요청이 "Lock wait timeout exceeded"로 실패했다.

앱 코드 쪽 세션은 전부 get_session()의 try/finally나 명시적 finally로
db.close()를 부르고 있어(확인함) 정상 종료 경로에서 새는 곳은 없다 — 이번
건은 컨테이너가 재시작되며 연결이 **비정상 종료**된 경우로, 애플리케이션
코드가 개입할 여지가 없다. 그래서 반대편(주기적으로 방치된 트랜잭션을 찾아
직접 끊는 쪽)에 안전망을 둔다.
"""

from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.shared.logging_config import get_logger, log_event

logger = get_logger(__name__)

# 이보다 오래 유휴 상태(쿼리 없이 트랜잭션만 열어 둔 채)인 세션은 강제로 끊는다.
# 정상적인 요청 하나가 이만큼 오래 걸릴 일은 없다(가장 무거운 대용량 로그 스캔도
# 비동기 job이라 개별 DB 트랜잭션은 몇 초 안에 끝난다) — 그래서 여유 있게 잡아도
# 오탐(멀쩡한 트랜잭션을 끊는 일)이 없다.
STALE_TRANSACTION_SECONDS = 180


def kill_stale_transactions(db: Session, idle_seconds: int = STALE_TRANSACTION_SECONDS) -> int:
    """idle_seconds보다 오래 아무 쿼리 없이 열려만 있는 트랜잭션을 찾아 끊는다.

    돌려주는 값은 끊은 세션 수. TIDB_TRX는 TiDB 전용 information_schema
    뷰라(MySQL의 innodb_trx와 다르다) 로컬 MySQL 개발 환경에서는 이 뷰 자체가
    없을 수 있다 — 그 경우도 예외를 삼키고 0을 돌려준다(안전망이 없어도
    스캐너 본 기능은 그대로 돌아야 한다는 이 프로젝트의 원칙과 같다).
    """
    try:
        rows = db.execute(
            text(
                """
                SELECT SESSION_ID, TIMESTAMPDIFF(SECOND, START_TIME, NOW()) AS age_seconds
                FROM information_schema.TIDB_TRX
                WHERE STATE = 'Idle' AND TIMESTAMPDIFF(SECOND, START_TIME, NOW()) > :idle_seconds
                """
            ),
            {"idle_seconds": idle_seconds},
        ).fetchall()
    except Exception as exc:  # noqa: BLE001 — TIDB_TRX가 없는 환경(로컬 MySQL 등)도 있다
        log_event(logger, logging.DEBUG, "db.lock_reaper.unavailable", error_code=type(exc).__name__)
        return 0

    killed = 0
    for db_connection_id, age_seconds in rows:
        try:
            db.execute(text(f"KILL {int(db_connection_id)}"))
            killed += 1
            log_event(
                logger, logging.WARNING, "db.lock_reaper.killed",
                db_connection_id=int(db_connection_id), idle_seconds=int(age_seconds),
            )
        except Exception as exc:  # noqa: BLE001 — 그 사이 세션이 알아서 끝났을 수도 있다
            log_event(
                logger, logging.DEBUG, "db.lock_reaper.kill_failed",
                db_connection_id=int(db_connection_id), error_code=type(exc).__name__,
            )
    return killed
