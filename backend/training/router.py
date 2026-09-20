from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db.session import get_session
from backend.db.tables import TrainingEvent, TrainingProgress
from backend.shared.logging_config import get_logger, log_event
from backend.training.defender import generate_defender_report
from backend.training.scenarios import select_random_scenario
from backend.training.session_store import TrainingJsonStore
from backend.training.training_flow import (
    create_training_session,
    generate_attacker_message,
    process_user_reply,
)
from backend.training.training_service import (
    calculate_training_score,
    finish_training,
    grade_training_score,
    finish_unscored_training,
)


logger = get_logger(__name__)
router = APIRouter(prefix="/training", tags=["training"])


class TrainingStartRequest(BaseModel):
    user_id: int
    level: int = Field(ge=1, le=5)


class TrainingReplyRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10_000)


# Uvicorn worker들은 메모리를 공유하지 않는다. 시작과 답장 요청이 서로
# 다른 worker에 배정되어도 이어지도록 컨테이너 공용 임시 디스크에 저장한다.
_training_sessions = TrainingJsonStore("infoguard_training_sessions")
_training_reports = TrainingJsonStore("infoguard_training_reports")


def _record_training_event(
    db: Session, training_progress_id: int, turn_no: int, shared_fields: list[str]
) -> None:
    """이 턴에 사용자가 개인정보를 새로 공유했는지 기록한다.

    sanitize_training_text()는 정규식 5종(rrn/card/account/phone/email)만 보는
    경량 검사라 scan.scan_text()의 Finding을 만들지 않는다 — 그래서
    save_scan_result()로 못 넣고 TrainingEvent에 직접 기록한다.

    detected_field는 컬럼 하나뿐이고 (training_progress_id, turn_no)에 유니크
    제약이 걸려 있어서, 한 턴에 여러 유형을 같이 공유해도 첫 번째 유형만 남는다 —
    정밀 탐지 로그가 아니라 "이 턴에 위험한 공유가 있었는가"를 보는 용도다.

    main.py의 _persist_scan_results와 같은 이유로 실패해도 답장 처리 자체는
    막지 않는다 — 저장은 선택이지 훈련 진행의 전제조건이 아니다.
    """
    try:
        db.add(
            TrainingEvent(
                training_progress_id=training_progress_id,
                turn_no=turn_no,
                detected_field=shared_fields[0] if shared_fields else None,
                action="경고표시" if shared_fields else None,
            )
        )
        db.commit()
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        log_event(
            logger,
            logging.WARNING,
            "training.event.persist.failed",
            error_code=type(exc).__name__,
        )


def _complete_training(
    *,
    db: Session,
    training_progress_id: int,
    session: dict,
) -> dict:
    defender_report = generate_defender_report(
        level=session["level"],
        scenario=session["scenario"],
        history=session["history"],
        shared_fields=session["shared_fields"],
    )
    score = calculate_training_score(defender_report)
    grade = grade_training_score(score)
    finish_training(
        db=db,
        training_progress_id=training_progress_id,
        final_score=score,
    )
    report = {
        "training_progress_id": training_progress_id,
        "level": session["level"],
        "scenario_id": session["scenario_id"],
        "scenario_title": session["scenario"]["name"] if session.get("scenario") else None,
        "score": score,
        "grade": grade,
        "risky_actions": defender_report["risky_actions"],
        "good_actions": defender_report["good_actions"],
        "improvements": defender_report["improvements"],
        "summary": defender_report["summary"],
        # training_flow stores only sanitized user text in history.  Copy the
        # records into the report before the short-lived session is removed so
        # the PDF can show the real exchange without exposing the raw input.
        "conversation": [
            {"role": message["role"], "content": message["content"]}
            for message in session["history"]
        ],
    }
    _training_reports[training_progress_id] = report
    # 세션에는 치환된 대화만 있지만 완료 후 즉시 제거한다.
    _training_sessions.pop(training_progress_id, None)
    return report


def _complete_unscored_training(
    *,
    db: Session,
    training_progress_id: int,
    session: dict,
) -> dict:
    finish_unscored_training(db, training_progress_id)
    report = {
        "training_progress_id": training_progress_id,
        "level": session["level"],
        "scenario_id": session["scenario_id"],
        "scenario_title": session["scenario"]["name"] if session.get("scenario") else None,
        "score": None,
        "grade": "평가 불가",
        "evaluation_status": "insufficient_responses",
        "risky_actions": [],
        "good_actions": [],
        "improvements": ["실제 상황에서 취할 대응을 문장으로 입력한 뒤 다시 훈련해 보세요."],
        "summary": "의미 있는 답변이 충분하지 않아 이번 훈련은 점수를 산정하지 않았습니다.",
        "conversation": [
            {"role": message["role"], "content": message["content"]}
            for message in session["history"]
        ],
    }
    _training_reports[training_progress_id] = report
    _training_sessions.pop(training_progress_id, None)
    return report


@router.post("/start")
def start_training_api(
    request: TrainingStartRequest,
    db: Session = Depends(get_session),
):
    try:
        progress = TrainingProgress(
            user_id=request.user_id,
            level=request.level,
            status="진행중",
            score=0,
        )
        db.add(progress)
        db.flush()

        scenario = select_random_scenario(request.level)
        session = create_training_session(request.level, scenario)
        attacker_message = generate_attacker_message(session)

        db.commit()
        db.refresh(progress)
        _training_sessions[progress.id] = session

        log_event(
            logger,
            logging.INFO,
            "training.started",
            training_level=request.level,
            scenario_id=scenario["id"],
            turn_no=session["turn_no"],
            training_status="in_progress",
        )
        return {
            "training_progress_id": progress.id,
            "level": request.level,
            "scenario_id": scenario["id"],
            "scenario_title": scenario["name"],
            "turn_no": session["turn_no"],
            "attacker_message": attacker_message,
        }
    except Exception as exc:
        db.rollback()
        log_event(
            logger,
            logging.ERROR,
            "training.start.failed",
            training_level=request.level,
            error_code=type(exc).__name__,
        )
        raise HTTPException(
            status_code=500,
            detail="훈련 시작 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.",
        ) from exc


@router.post("/{training_progress_id}/reply")
def reply_training_api(
    training_progress_id: int,
    request: TrainingReplyRequest,
    db: Session = Depends(get_session),
):
    session = _training_sessions.get(training_progress_id)
    if session is None:
        raise HTTPException(
            status_code=404,
            detail="진행 중인 훈련 세션을 찾을 수 없습니다.",
        )

    try:
        # Defender 호출만 실패한 경우 사용자가 같은 원문을 다시 보낼 필요 없이 재시도한다.
        if session["status"] in {"awaiting_report", "awaiting_unscored_report"}:
            complete = (
                _complete_unscored_training
                if session["status"] == "awaiting_unscored_report"
                else _complete_training
            )
            complete(db=db, training_progress_id=training_progress_id, session=session)
            return {
                "training_progress_id": training_progress_id,
                "turn_no": session["turn_no"],
                "is_finished": True,
                "attacker_message": None,
            }

        turn_no = session["turn_no"]
        result = process_user_reply(session=session, user_reply=request.text)
        if result["is_evaluable"]:
            _record_training_event(db, training_progress_id, turn_no, result["shared_fields"])
        if result["is_finished"]:
            complete = (
                _complete_unscored_training
                if result["evaluation_status"] == "insufficient_responses"
                else _complete_training
            )
            complete(
                db=db,
                training_progress_id=training_progress_id,
                session=session,
            )
            next_message = None
        else:
            next_message = generate_attacker_message(session)
            # File-backed store returns a detached value, unlike the old dict.
            # Persist mutations made by process_user_reply/generate_attacker_message.
            _training_sessions[training_progress_id] = session

        log_event(
            logger,
            logging.INFO,
            "training.reply.processed",
            turn_no=result["turn_no"],
            training_status="finished" if result["is_finished"] else "in_progress",
            is_evaluable=result["is_evaluable"],
            shared_field_types=result["shared_fields"],
        )
        return {
            "training_progress_id": training_progress_id,
            "turn_no": result["turn_no"],
            "is_finished": result["is_finished"],
            "attacker_message": next_message,
            "evaluation_status": result["evaluation_status"],
            "invalid_reply_count": result["invalid_reply_count"],
        }
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except Exception as exc:
        db.rollback()
        log_event(
            logger,
            logging.ERROR,
            "training.reply.failed",
            error_code=type(exc).__name__,
        )
        raise HTTPException(
            status_code=500,
            detail="답장 처리 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.",
        ) from exc


@router.get("/{training_progress_id}/report")
def get_training_report_api(
    training_progress_id: int,
    db: Session = Depends(get_session),
):
    progress = db.get(TrainingProgress, training_progress_id)
    if progress is None:
        raise HTTPException(status_code=404, detail="훈련 기록을 찾을 수 없습니다.")

    report = _training_reports.get(training_progress_id)
    if report is not None:
        return report

    session = _training_sessions.get(training_progress_id)
    if session and session["status"] in {"awaiting_report", "awaiting_unscored_report"}:
        try:
            complete = (
                _complete_unscored_training
                if session["status"] == "awaiting_unscored_report"
                else _complete_training
            )
            return complete(
                db=db,
                training_progress_id=training_progress_id,
                session=session,
            )
        except Exception as exc:
            db.rollback()
            log_event(
                logger,
                logging.ERROR,
                "training.report.failed",
                error_code=type(exc).__name__,
            )
            raise HTTPException(
                status_code=500,
                detail="훈련 리포트 생성 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.",
            ) from exc

    raise HTTPException(
        status_code=409,
        detail="훈련이 아직 완료되지 않았거나 상세 리포트가 만료되었습니다.",
    )


_GRADE_ORDER = ("안전", "양호", "주의", "위험")


@router.get("/stats/{level}")
def get_training_stats(
    level: int = Path(ge=1, le=5),
    score: int | None = Query(default=None, ge=0, le=100),
    db: Session = Depends(get_session),
) -> dict:
    """이 레벨에서 완료된 훈련들의 집계. 리포트 화면의 "평균 대비 내 점수" 문구에 쓴다.

    training_progress_id 경로 파라미터는 int라서, "/training/stats/2"의 "stats"는
    거기 매칭이 안 되고(정수 변환 실패) 자연히 이 라우트로 넘어온다 — 경로 등록
    순서를 신경 쓸 필요가 없다.

    score를 같이 주면 백분위(percentile)도 계산한다 — "당신은 상위 30%입니다" 같은
    문구에 필요한 값이다. score를 안 주면 백분위는 null로 나간다.
    완료된 훈련이 하나도 없으면 average_score/percentile 전부 null이다 — 0으로
    두면 "평균 0점"처럼 보여서 데이터가 없는 것과 실제로 0점인 것을 구분 못 한다.
    """
    scores = [
        row[0]
        for row in db.query(TrainingProgress.score)
        .filter(
            TrainingProgress.level == level,
            TrainingProgress.completed_at.isnot(None),
            TrainingProgress.status == "완료",
        )
        .all()
    ]

    grade_distribution = {grade: 0 for grade in _GRADE_ORDER}
    for value in scores:
        grade_distribution[grade_training_score(value)] += 1

    percentile = None
    if score is not None and scores:
        # "상위 X%"는 나보다 낮거나 같은 점수의 비율로 계산한다.
        not_better = sum(1 for value in scores if value <= score)
        percentile = round(100 * not_better / len(scores))

    return {
        "level": level,
        "completed_count": len(scores),
        "average_score": round(sum(scores) / len(scores), 1) if scores else None,
        "grade_distribution": grade_distribution,
        "percentile": percentile,
    }
