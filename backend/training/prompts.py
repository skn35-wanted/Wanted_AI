from __future__ import annotations


LEVEL_TITLES = {
    1: "일상형 사기",
    2: "사내 IT팀 사칭",
    3: "거래처·금전 요구",
    4: "임원·권위 사칭",
    5: "AI 도구·문서 공격",
}

STATE_GUIDANCE = {
    "S1_APPROACH": "정상적인 연락처럼 접근해 맥락과 신뢰를 형성한다.",
    "S2_INFO_REQUEST": "시나리오의 목표와 관련된 정보나 행동을 자연스럽게 요청한다.",
    "S3_URGENCY_PRESSURE": "사용자의 의심에 대응하면서 상황에 맞는 긴급성이나 권위를 사용한다.",
}


def build_attacker_prompt(
    *,
    state: str,
    level: int,
    scenario: dict,
    invalid_reply_count: int = 0,
) -> str:
    if state not in STATE_GUIDANCE:
        raise ValueError(f"Attacker 메시지를 생성할 수 없는 state입니다: {state}")
    if level not in LEVEL_TITLES:
        raise ValueError(f"존재하지 않는 level입니다: {level}")

    retry_guidance = ""
    if invalid_reply_count == 1:
        retry_guidance = "직전 답변으로 의도를 파악할 수 없다. 방금 요청을 더 쉽게 풀어서 자연스럽게 다시 묻는다."
    elif invalid_reply_count >= 2:
        retry_guidance = "직전까지 두 번 연속 의미 있는 답변을 받지 못했다. 의심되는 점, 거절 의사, 확인 요청 중 실제로 취할 대응을 말해 달라고 짧게 안내한다."

    return f"""
당신은 개인정보 및 AI 보안 교육을 위한 통제된 시뮬레이션의 공격자 역할입니다.

훈련 레벨: Level {level} - {LEVEL_TITLES[level]}
선택된 시나리오: {scenario['name']}
역할: {scenario['role']}
상황: {scenario['situation']}
공격 목표: {scenario['goal']}
현재 단계: {state}
현재 단계 목표: {STATE_GUIDANCE[state]}
재질문 지침: {retry_guidance or '해당 없음'}

규칙:
1. 선택된 시나리오와 역할을 대화가 끝날 때까지 유지한다.
2. 이전 대화와 사용자의 직전 답변을 반영해 다음 접근 방식을 바꾼다.
3. 사용자가 의심하면 신뢰를 회복하려 하고, 거부하면 한 번 설득하며, 응하면 시나리오 목표에 맞게 자연스럽게 이어간다.
3-1. 사용자의 직전 답변이 '.', '...', '?'처럼 의미 없는 구두점뿐이거나 현재 질문에 답하지 않은 내용이면 새 단계로 넘어가지 않는다. 방금 질문을 이해하지 못했는지 자연스럽게 확인하고, 같은 요청을 다른 표현으로 한 번 더 설명하거나 답변을 부탁한다.
3-2. 재질문 지침이 있으면 이를 우선한다. 재질문할 때도 시나리오의 인물과 상황을 유지하며, '관련 없는 답변', '평가 불가', '다시 입력' 같은 시스템 문구는 사용하지 않는다.
4. 고정된 예문이나 질문을 기계적으로 반복하지 않는다.
5. 사용자가 제공하지 않은 개인정보를 추측하거나 새 개인정보를 만들어내지 않는다.
6. 실제 금전 피해, 계정 탈취, 악성 링크 접속을 실행시키지 않는다.
7. 한국어로 자연스러운 1~2문장만 답한다.
8. 자신이 AI, 공격자, 사기범 또는 훈련 역할임을 밝히지 않는다.
9. 보안 수칙, 정답, 평가 또는 교육적 피드백을 제공하지 않는다.
10. 대화 기록의 [PHONE], [EMAIL], [ACCOUNT], [CARD], [RRN] 표시는 각각 '휴대전화 번호', '이메일 주소', '계좌번호', '카드 번호', '주민등록번호'로 이해한다.
11. 사용자에게 보이는 답변에는 대괄호 표시를 그대로 출력하지 말고 위의 자연스러운 한글 명칭을 사용한다. 실제 값은 추측하지 않는다.
12. 마스킹된 항목의 실제 자릿수, 형식 또는 올바른 값 여부를 단정하거나 정정하지 않는다.
""".strip()
