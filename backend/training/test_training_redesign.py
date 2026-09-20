import unittest
from unittest.mock import patch

from backend.training.sanitizer import sanitize_training_text
from backend.training.prompts import build_attacker_prompt
from backend.training.scenarios import SCENARIOS
from backend.training.training_flow import (
    MAX_INVALID_REPLIES,
    MAX_USER_TURNS,
    create_training_session,
    generate_attacker_message,
    process_user_reply,
)
from backend.training.training_service import (
    calculate_training_score,
    grade_training_score,
)
from backend.training.router import _complete_training, _complete_unscored_training
from backend.training.defender import _normalize_report


class TrainingRedesignTests(unittest.TestCase):
    def test_each_level_has_six_unique_scenarios(self):
        self.assertEqual(set(SCENARIOS), {1, 2, 3, 4, 5})
        ids = []
        for scenarios in SCENARIOS.values():
            self.assertEqual(len(scenarios), 6)
            ids.extend(scenario["id"] for scenario in scenarios)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len(ids), 30)

    def test_training_sanitizer_replaces_only_explicit_formats(self):
        result = sanitize_training_text(
            "홍길동 docX-ray 서울 010-1234-5678 test@example.com "
            "110-123-456789 4111-1111-1111-1111 990101-1234567"
        )
        self.assertEqual(
            result["sanitized_text"],
            "홍길동 docX-ray 서울 [PHONE] [EMAIL] [ACCOUNT] [CARD] [RRN]",
        )
        self.assertEqual(
            result["shared_fields"],
            ["rrn", "card", "account", "phone", "email"],
        )

    def test_session_keeps_only_sanitized_user_text(self):
        session = create_training_session(1, SCENARIOS[1][0])
        session["history"].append(
            {"role": "assistant", "content": "연락처를 확인할게요."}
        )
        result = process_user_reply(
            session=session,
            user_reply="제 번호는 010-1234-5678입니다.",
        )
        self.assertEqual(result["shared_fields"], ["phone"])
        self.assertEqual(
            session["history"][-1]["content"],
            "제 번호는 [PHONE]입니다.",
        )
        self.assertNotIn("010-1234-5678", repr(session))

    def test_attacker_prompt_hides_internal_privacy_tokens_from_user(self):
        prompt = build_attacker_prompt(
            state="S2_INFO_REQUEST",
            level=1,
            scenario=SCENARIOS[1][0],
        )
        self.assertIn("대괄호 표시를 그대로 출력하지 말고", prompt)
        self.assertIn("휴대전화 번호", prompt)
        self.assertIn("카드 번호", prompt)
        self.assertIn("같은 요청을 다른 표현으로 한 번 더", prompt)
        self.assertIn("시스템 문구는 사용하지 않는다", prompt)

    def test_invalid_replies_reask_twice_then_finish_without_score(self):
        session = create_training_session(3, SCENARIOS[3][0])
        original_state = session["state"]

        for count in range(1, MAX_INVALID_REPLIES):
            result = process_user_reply(session=session, user_reply="...")
            self.assertFalse(result["is_evaluable"])
            self.assertFalse(result["is_finished"])
            self.assertEqual(result["invalid_reply_count"], count)
            self.assertEqual(session["state"], original_state)
            self.assertEqual(session["turn_no"], 1)

        result = process_user_reply(session=session, user_reply=".")
        self.assertTrue(result["is_finished"])
        self.assertEqual(result["evaluation_status"], "insufficient_responses")
        self.assertEqual(session["status"], "awaiting_unscored_report")
        self.assertEqual(session["turn_no"], 1)

    def test_meaningful_reply_resets_invalid_reply_count(self):
        session = create_training_session(3, SCENARIOS[3][0])
        process_user_reply(session=session, user_reply=".")
        result = process_user_reply(
            session=session,
            user_reply="공식 대표번호로 확인하겠습니다.",
        )
        self.assertTrue(result["is_evaluable"])
        self.assertEqual(result["invalid_reply_count"], 0)

    def test_unscored_report_has_no_score_or_grade(self):
        session = create_training_session(3, SCENARIOS[3][0])
        session["history"] = [
            {"role": "assistant", "content": "담당자 연락처를 알려주세요."},
            {"role": "user", "content": "."},
        ]
        with patch("backend.training.router.finish_unscored_training"):
            report = _complete_unscored_training(
                db=object(),
                training_progress_id=123456,
                session=session,
            )
        self.assertIsNone(report["score"])
        self.assertEqual(report["grade"], "평가 불가")
        self.assertEqual(report["evaluation_status"], "insufficient_responses")

    def test_non_disclosure_is_moved_from_risky_to_good_actions(self):
        safe_action = "담당자 성함과 직통 연락처를 요청받았으나 제공하지 않음"
        raw = {
            "verified_identity": False,
            "used_official_channel": False,
            "shared_personal_info": False,
            "shared_auth_info": False,
            "accepted_money_request": False,
            "accepted_suspicious_link": False,
            "maintained_verification_under_pressure": False,
            "risky_actions": [safe_action],
            "good_actions": [],
            "improvements": [],
            "summary": "개인정보를 제공하지 않았습니다.",
        }
        report = _normalize_report(raw, [])
        self.assertEqual(report["risky_actions"], [])
        self.assertIn(safe_action, report["good_actions"])

    def test_completed_verification_is_not_recommended_again(self):
        raw = {
            "verified_identity": True,
            "used_official_channel": True,
            "shared_personal_info": False,
            "shared_auth_info": False,
            "accepted_money_request": False,
            "accepted_suspicious_link": False,
            "maintained_verification_under_pressure": True,
            "risky_actions": [],
            "good_actions": ["공식 대표번호로 발신자를 확인했습니다."],
            "improvements": [
                "발신자의 신원을 확인하기 위한 추가적인 절차를 고려하세요.",
                "공식 채널로 요청을 다시 확인하세요.",
            ],
            "summary": "안전하게 대응했습니다.",
        }

        report = _normalize_report(raw, [])

        self.assertEqual(report["improvements"], [])

    def test_max_turn_finishes_without_calling_attacker(self):
        session = create_training_session(2, SCENARIOS[2][0])
        session["turn_no"] = MAX_USER_TURNS
        result = process_user_reply(session=session, user_reply="확인해 보겠습니다.")
        self.assertTrue(result["is_finished"])
        self.assertEqual(session["state"], "END")
        self.assertEqual(session["status"], "awaiting_report")

        with patch(
            "backend.training.training_flow.AttackerService",
            side_effect=AssertionError("Attacker must not be created"),
        ):
            with self.assertRaisesRegex(ValueError, "종료된 훈련"):
                generate_attacker_message(session)

    def test_backend_calculates_fixed_score_and_grade(self):
        safe = {
            "verified_identity": True,
            "used_official_channel": True,
            "shared_personal_info": False,
            "shared_auth_info": False,
            "accepted_money_request": False,
            "accepted_suspicious_link": False,
            "maintained_verification_under_pressure": True,
        }
        risky = {
            **safe,
            "verified_identity": False,
            "used_official_channel": False,
            "shared_personal_info": True,
            "shared_auth_info": True,
            "accepted_money_request": True,
            "accepted_suspicious_link": True,
            "maintained_verification_under_pressure": False,
        }
        self.assertEqual(calculate_training_score(safe), 100)
        self.assertEqual(grade_training_score(100), "안전")
        self.assertEqual(calculate_training_score(risky), 0)
        self.assertEqual(grade_training_score(0), "위험")

        cautious_refusal = {
            **safe,
            "verified_identity": False,
            "used_official_channel": False,
        }
        self.assertEqual(calculate_training_score(cautious_refusal), 95)
        self.assertEqual(grade_training_score(95), "안전")

        # 신원 확인/공식 채널 재확인/압박 유지 세 항목을 전부 못 했어도, 피해
        # 행동(개인정보·인증정보 공유, 송금·링크 수락)이 0건이면 최소 90점(안전)은
        # 보장되어야 한다 — 절차 미흡이 실질적 무피해보다 더 나쁘게 채점되면 안 된다.
        no_process_but_no_harm = {
            **safe,
            "verified_identity": False,
            "used_official_channel": False,
            "maintained_verification_under_pressure": False,
        }
        self.assertEqual(calculate_training_score(no_process_but_no_harm), 90)
        self.assertEqual(grade_training_score(90), "안전")

    def test_completed_report_keeps_sanitized_conversation_and_scenario(self):
        scenario = SCENARIOS[1][0]
        session = create_training_session(1, scenario)
        session["history"].append(
            {"role": "assistant", "content": "연락처를 알려주세요."}
        )
        process_user_reply(
            session=session,
            user_reply="제 번호는 010-1234-5678입니다.",
        )
        defender_report = {
            "risky_actions": [],
            "good_actions": ["공식 채널을 확인했습니다."],
            "improvements": [],
            "summary": "안전하게 대응했습니다.",
        }

        with patch(
            "backend.training.router.generate_defender_report",
            return_value=defender_report,
        ), patch(
            "backend.training.router.calculate_training_score",
            return_value=100,
        ), patch(
            "backend.training.router.grade_training_score",
            return_value="안전",
        ), patch("backend.training.router.finish_training"):
            report = _complete_training(
                db=object(),
                training_progress_id=987654,
                session=session,
            )

        self.assertEqual(report["scenario_id"], scenario["id"])
        self.assertEqual(report["scenario_title"], scenario["name"])
        self.assertEqual(
            report["conversation"],
            [
                {"role": "assistant", "content": "연락처를 알려주세요."},
                {"role": "user", "content": "제 번호는 [PHONE]입니다."},
            ],
        )
        self.assertNotIn("010-1234-5678", repr(report))


if __name__ == "__main__":
    unittest.main()
