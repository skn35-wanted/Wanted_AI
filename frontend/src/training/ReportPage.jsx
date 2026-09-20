import { useCallback, useEffect, useRef, useState } from 'react'
import { api } from '../shared/api.js'
import { Button, Card, DecodeText } from '../shared/components/index.js'
import { displayMaskedText, getRecommendedResponse } from './trainingPrivacyGuidance.js'
import './training.css'

// 훈련 결과 리포트. 하단에 스캐너로 넘어가는 전환 버튼이 있다.
export default function ReportPage({ training, navigate }) {
  const [report, setReport] = useState(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [savingPdf, setSavingPdf] = useState(false)

  // 완료된 리포트를 조회한다. 개발 모드(StrictMode)에서 effect가 두 번 돌아
  // 같은 요청을 중복 전송하지 않도록 이미 요청한 훈련 id를 기억한다.
  const requestedId = useRef(null)
  const trainingId = training?.id

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      setReport(await api.trainingReport(trainingId))
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [trainingId])

  useEffect(() => {
    if (trainingId == null || requestedId.current === trainingId) return
    requestedId.current = trainingId
    load()
  }, [trainingId, load])

  async function downloadReport() {
    if (!report) return
    setSavingPdf(true)
    setError('')
    try {
      const { downloadTrainingReportPdf } = await import('./reportPdf.js')
      await downloadTrainingReportPdf(report)
    } catch (err) {
      setError(err.message || 'PDF를 생성하지 못했습니다. 다시 시도해 주세요.')
    } finally {
      setSavingPdf(false)
    }
  }

  if (!training) {
    return (
      <div className="container report-page">
        <Card title="진행한 훈련이 없습니다" description="훈련 모드에서 레벨을 골라 먼저 진행해 주세요.">
          <Button onClick={() => navigate('training')}>훈련 시작하기</Button>
        </Card>
      </div>
    )
  }

  return (
    <div className="container report-page">
      <button type="button" className="back-link" onClick={() => navigate('training')}>
        ← 훈련 모드로 돌아가기
      </button>
      <header>
        <p className="eyebrow">TRAINING REPORT</p>
        <h1 className="page-title">훈련 결과</h1>
        <p className="page-desc">대화 원문은 저장하지 않고, 어떤 정보를 어떻게 다뤘는지만 기록해 분석합니다.</p>
      </header>

      {loading && (
        <Card tone="muted">
          <p className="report-loading" aria-live="polite">
            <span className="spinner" aria-hidden="true" /> 훈련 결과를 불러오고 있습니다…
          </p>
        </Card>
      )}

      {error && (
        <div className="stack stack--tight">
          <p className="alert alert--error" role="alert">
            {error}
          </p>
          <div className="row">
            <Button variant="secondary" onClick={load}>
              다시 시도
            </Button>
          </div>
        </div>
      )}

      {report && (
        <>
          <section className={`report-hero report-hero--${report.score == null ? 'unscored' : report.grade}`}>
            <div>
              <p className="eyebrow">SECURITY SCORE</p>
              <p className="report-score">
                <b>{report.score == null ? '—' : report.score}</b>
                <span>{report.score == null ? '점수 없음' : '/ 100'}</span>
              </p>
            </div>
            <div className="report-grade">
              <span>Case {report.level}</span>
              <strong>{report.grade}</strong>
              <small>대응 등급</small>
            </div>
          </section>

          <section className="report-summary" aria-labelledby="report-summary-title">
            <p className="eyebrow">AI DEFENDER</p>
            <h2 id="report-summary-title">종합 분석</h2>
            <p>{report.summary || '분석 결과가 없습니다.'}</p>
          </section>

          {report.score == null ? (
            <section className="report-detail report-detail--improve">
              <span className="report-detail__icon" aria-hidden="true">→</span>
              <h2>다시 훈련하려면</h2>
              <ul>{report.improvements.map((item) => <li key={item}>{item}</li>)}</ul>
            </section>
          ) : (
            <div className="report-grid">
              <section className="report-detail report-detail--risk">
                <span className="report-detail__icon" aria-hidden="true">!</span>
                <h2>위험했던 행동</h2>
                {report.risky_actions?.length ? (
                  <ul>{report.risky_actions.map((item) => <li key={item}>{item}</li>)}</ul>
                ) : <p>확인된 위험 행동이 없습니다.</p>}
              </section>
              <section className="report-detail report-detail--good">
                <span className="report-detail__icon" aria-hidden="true">✓</span>
                <h2>잘한 점</h2>
                {report.good_actions?.length ? (
                  <ul>{report.good_actions.map((item) => <li key={item}>{item}</li>)}</ul>
                ) : <p>확인된 항목이 없습니다.</p>}
              </section>
              <section className="report-detail report-detail--improve">
                <span className="report-detail__icon" aria-hidden="true">→</span>
                <h2>다음에는 이렇게</h2>
                {report.improvements?.length ? (
                  <ul>{report.improvements.map((item) => <li key={item}>{item}</li>)}</ul>
                ) : <p>추가 개선 권고가 없습니다.</p>}
              </section>
            </div>
          )}

          {report.conversation?.length > 0 && (
            <section className="report-conversation" aria-labelledby="report-conversation-title">
              <div className="report-conversation__heading">
                <div>
                  <p className="eyebrow">TRAINING REVIEW</p>
                  <h2 id="report-conversation-title">AI와 나의 실전 대화 기록</h2>
                </div>
                <span className="report-conversation__scenario">
                  LEVEL {String(report.level).padStart(2, '0')} · {report.scenario_title || '훈련 시나리오'}
                </span>
              </div>

              <ol className="report-conversation__list">
                {report.conversation.map((message, index) => {
                  const isUser = message.role === 'user'
                  const turn = Math.floor(index / 2) + 1
                  const recommendation = isUser ? getRecommendedResponse(message.content) : null

                  return (
                    <li key={`${message.role}-${index}`} className="report-conversation__entry">
                      <article className={`report-message report-message--${isUser ? 'user' : 'attacker'}`}>
                        <span className="report-message__label">
                          {isUser ? '나의 대응' : 'AI 사기범'} · TURN {String(turn).padStart(2, '0')}
                        </span>
                        <p>{displayMaskedText(message.content)}</p>
                      </article>

                      {recommendation && (
                        <aside className="report-recommendation">
                          <span>적절한 대응</span>
                          <p>{recommendation}</p>
                        </aside>
                      )}
                    </li>
                  )
                })}
              </ol>
            </section>
          )}
        </>
      )}

      <div className="cta-card rv">
        <div>
          <b>이제 내 문서도 검사해 보세요.</b>
          <p>보내기 전에 문서 속 개인정보와 숨은 명령을 DocX-ray가 찾아 드립니다.</p>
        </div>
        <div className="report-page__actions">
          {report && (
            <Button variant="secondary" onClick={downloadReport} disabled={savingPdf}>
              {savingPdf ? 'PDF 생성 중…' : '결과 저장하기 (PDF)'}
            </Button>
          )}
          <Button onClick={() => navigate('')}>스캐너로 내 문서 검사하기 →</Button>
          <Button variant="secondary" onClick={() => navigate('training')}>
            다시 훈련하기
          </Button>
        </div>
      </div>
    </div>
  )
}
