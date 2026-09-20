"""backend/db/lock_reaper.py가 방치된 TiDB 트랜잭션을 찾아 끊는지 확인한다.

실측(2026-09-20): PR #60의 미해결 머지 충돌로 배포가 502 크래시 루프를 도는
동안, 요청 하나를 처리하던 워커가 DB 트랜잭션을 연 채 재시작돼 그 트랜잭션이
TiDB 쪽에 15분 넘게 "Sleep, in transaction" 상태로 남았다. 그 트랜잭션이 잡은
락 때문에 training_progress에 새로 쓰는 모든 요청이 "Lock wait timeout
exceeded"로 실패했다 — kill_stale_transactions로 직접 끊어 확인했고, 재발을
막기 위해 main.py가 주기적으로(60초마다) 이 함수를 부른다.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, call

from backend.db.lock_reaper import kill_stale_transactions


class KillStaleTransactionsTest(unittest.TestCase):
    def test_kills_each_stale_session_found(self) -> None:
        db = MagicMock()
        select_result = MagicMock()
        select_result.fetchall.return_value = [(111, 200), (222, 500)]
        kill_result = MagicMock()
        # 첫 execute는 SELECT(TIDB_TRX), 그 뒤 두 번은 각 세션에 대한 KILL이다.
        db.execute.side_effect = [select_result, kill_result, kill_result]

        killed = kill_stale_transactions(db, idle_seconds=180)

        self.assertEqual(killed, 2)
        # 1번(TIDB_TRX 조회) + 세션당 1번(KILL) = 3번 execute.
        self.assertEqual(db.execute.call_count, 3)

    def test_returns_zero_when_nothing_stale(self) -> None:
        db = MagicMock()
        select_result = MagicMock()
        select_result.fetchall.return_value = []
        db.execute.return_value = select_result

        killed = kill_stale_transactions(db)

        self.assertEqual(killed, 0)

    def test_missing_tidb_trx_view_is_handled_gracefully(self) -> None:
        """TIDB_TRX가 없는 환경(로컬 MySQL 등)에서도 예외를 삼키고 0을 돌려준다 —
        안전망이 없다고 스캐너 본 기능까지 죽으면 안 된다는 이 프로젝트의 원칙과 같다."""
        db = MagicMock()
        db.execute.side_effect = Exception("no such table")

        killed = kill_stale_transactions(db)

        self.assertEqual(killed, 0)

    def test_one_kill_failing_does_not_stop_the_others(self) -> None:
        db = MagicMock()
        select_result = MagicMock()
        select_result.fetchall.return_value = [(111, 200), (222, 500)]
        db.execute.side_effect = [select_result, Exception("already gone"), MagicMock()]

        killed = kill_stale_transactions(db)

        self.assertEqual(killed, 1)


if __name__ == "__main__":
    unittest.main()
