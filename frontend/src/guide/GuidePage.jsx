import {
  ChevronRight,
  EyeOff,
  FileDown,
  FileUp,
  Info,
  List,
  MessageCircle,
  ScanSearch,
  Search,
  TriangleAlert,
} from 'lucide-react'
import { UPLOAD_LIMITS } from '../shared/api.js'
import { Badge, Button, DecodeText, GlowCard } from '../shared/components/index.js'
import './guide.css'

// 아이콘은 훈련 모드 소개 카드(FEATURES)와 같은 Lucide line icon 세트를 쓴다.
//   FileUp 파일 업로드 / ScanSearch AI가 훑어 찾는 동작("검사") / TriangleAlert 위험 경고 / EyeOff 가려서 안 보이게(마스킹)
const STEPS = [
  {
    number: '01',
    Icon: FileUp,
    title: '문서 업로드',
    copy: `PDF·Word·Excel·텍스트 파일을 한 번에 최대 ${UPLOAD_LIMITS.maxFiles}개, 파일당 ${UPLOAD_LIMITS.maxFileBytes / (1024 * 1024)}MB까지 업로드 가능합니다.`,
    note: '이미지는 신분증만 지원합니다.',
  },
  {
    number: '02',
    Icon: ScanSearch,
    title: '개인정보·숨은 명령 검사',
    copy: '문서 안의 개인정보와, 눈에 보이지 않게 심긴 AI 지시문을 함께 찾습니다.',
  },
  {
    number: '03',
    Icon: TriangleAlert,
    title: '검사 결과 확인',
    copy: '파일별 위험도와 함께, 문서 어느 위치에서 무엇이 나왔는지 확인합니다.',
  },
  {
    number: '04',
    Icon: EyeOff,
    title: '안전하게 마스킹',
    copy: '원본 형식 그대로 위험 요소만 가린 사본을 만들어 내려받습니다.',
  },
]

// backend/shared/schema.py의 RiskType과 같은 묶음이다. 유형을 늘리거나 줄이면 여기도 같이 고친다.
const SCAN_TARGETS = [
  { title: '개인정보', items: ['이름', '전화번호', '이메일', '주소', '생년월일', '사번'] },
  { title: '고유식별정보', items: ['주민등록번호', '여권번호', '운전면허번호', '외국인등록번호'] },
  { title: '금융·인증정보', items: ['계좌번호', '카드번호', 'API 키', 'DB 접속정보'] },
  { title: '기업·조직정보', items: ['사업자등록번호', '법인등록번호', 'IP 주소', '조직명'] },
]

const HIDDEN_TARGETS = [
  '숨겨진 지시문',
  '흰 글씨·0pt 텍스트',
  '보이지 않는 문자',
  '숨긴 행·열·시트',
  '이미지에 가려진 글자',
]

// 라벨은 결과 화면에 나가는 것과 같아야 한다(high/medium/low -> 위험/주의/발견없음).
const LEVELS = [
  { key: 'high', label: '위험', copy: '외부로 보내기 전에 반드시 확인해야 할 항목이 있습니다.' },
  { key: 'medium', label: '주의', copy: '개인정보나 민감정보가 있습니다. 받는 사람에 따라 가릴지 정하세요.' },
  { key: 'low', label: '발견없음', copy: '이번 검사에서 탐지된 항목이 없습니다.' },
]

const REVIEW_STEPS = [
  { step: 'STEP 1', title: '항목 고르기', copy: '위험·주의로 잡힌 항목을 목록에서 고릅니다.' },
  { step: 'STEP 2', title: '위치 확인', copy: '문서 어느 자리에서 나왔는지 확인합니다.' },
  { step: 'STEP 3', title: '원문과 비교', copy: '가리기 전과 후를 나란히 놓고 봅니다.' },
  { step: 'STEP 4', title: '사본 받기', copy: '여러 파일은 ZIP으로 한 번에 받습니다.' },
]

// 실제 엔진의 전체 마스킹 출력 형식이다(backend.shared.schema.mask_placeholder).
const MASK_ROWS = [
  { label: '공급사', before: '주식회사 블루웨이브', after: [{ text: '주식회사 ' }, { text: '[조직명]', masked: true }] },
  { label: '대표', before: '김서연', after: [{ text: '[이름]', masked: true }] },
  { label: '사업자등록번호', before: '873-09-84584', after: [{ text: '[사업자등록번호]', masked: true }] },
  { label: '담당자 연락처', before: '010-1234-5678', after: [{ text: '[전화번호]', masked: true }] },
]

const HANDLING = [
  { term: '업로드한 원본', desc: '검사에만 쓰고, 검사가 끝나는 즉시 서버에서 지웁니다. 따로 저장하지 않습니다.' },
  { term: '마스킹한 사본', desc: '내려받을 수 있도록 임시로 두고, 30분이 지나면 자동으로 삭제합니다.' },
  { term: '데이터베이스', desc: '문서 원문은 남기지 않습니다. 무엇을 왜 탐지했는지에 대한 정제된 기록만 보관합니다.' },
  { term: '서버 기록', desc: '파일 이름과 문서 내용은 기록하지 않습니다. 처리 건수·소요 시간만 남깁니다.' },
]

const TRAINING_STEPS = [
  {
    number: '01',
    Icon: List,
    title: '훈련 상황 선택',
    copy: '일상부터 업무까지 다양한 상황 중 원하는 훈련을 선택하세요.',
  },
  {
    number: '02',
    Icon: MessageCircle,
    title: 'AI와 실전 대화',
    copy: 'AI가 보내는 메시지에 직접 답장하며 대응해 보세요.',
  },
  {
    number: '03',
    Icon: Search,
    title: '결과 확인',
    copy: 'AI가 대화 내용을 분석해 대응 결과를 알려드립니다.',
  },
  {
    number: '04',
    Icon: FileDown,
    title: '리포트 저장',
    copy: '나의 대응 결과와 개선점을 PDF로 저장하고 복습하세요.',
  },
]

const UPLOAD_BUTTON_SELECTOR = '#upload .dropzone .btn' // UploadPage.jsx의 goToUpload()가 쓰는 것과 같은 자리
const WAIT_FRAMES = 20 // 첫 화면이 그려지기를 기다리는 최대 프레임 수(약 0.3초, AppFooter.jsx와 같은 값)

// 섹션 머리. 훈련 리포트(ReportPage)와 같은 .eyebrow + .section-title 짝을 쓴다 —
// 제목만 두면 카드 제목(.guide-step__title)보다 가벼워 보여서 위계가 뒤집힌다.
// 번호는 걷어낸 사이드바가 하던 "몇 번째 단락인가"를 대신한다.
function SectionHead({ num, label, note, children }) {
  return (
    <header className="guide-section__head">
      <p className="eyebrow">
        <span className="eyebrow__num">{num}</span>
        {label}
      </p>
      <div className="guide-section__line">
        <h2 className="section-title guide-section__title">{children}</h2>
        {note ? <p className="guide-section__note">{note}</p> : null}
      </div>
    </header>
  )
}

export default function GuidePage({ navigate }) {
  // 첫 화면으로 옮긴 뒤, 그 화면이 그려지면 업로드 상자까지 스크롤하고 안의 버튼에 초점을 둔다.
  // 다른 화면이라 지금은 그 요소가 없으므로, 그려질 때까지 프레임마다 확인한다(AppFooter.jsx의 goToSection과 같은 방식).
  function goToUpload() {
    navigate('')
    let tries = 0
    const tick = () => {
      const target = document.querySelector(UPLOAD_BUTTON_SELECTOR)
      if (target) {
        const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
        document.getElementById('upload')?.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' })
        target.focus({ preventScroll: true })
        return
      }
      if (tries < WAIT_FRAMES) {
        tries += 1
        requestAnimationFrame(tick)
      }
    }
    requestAnimationFrame(tick)
  }

  return (
    <div className="container guide-page">
      <section className="guide-intro rv">
        <Badge>HOW IT WORKS</Badge>
        <h1 className="page-title">DocX-ray 이용 가이드</h1>
        <p className="page-desc">문서를 올리고, 결과를 읽고, 안전한 사본을 받기까지 알아야 할 것을 정리했습니다.</p>
      </section>

      <section className="guide-section rv">
        <SectionHead num="01" label="SCAN FLOW">4단계 검사</SectionHead>
        {/* 뜨는 효과(:hover transform)는 바깥 li가 갖고, 빛(GlowCard)은 안쪽 div가 갖는다.
            둘을 한 요소에 같이 두면 호버 중 transform이 걸리는 순간 GlowCard의
            background-attachment: fixed 좌표가 요소 로컬 좌표로 다시 해석돼 빛이 카드 밖으로 밀려난다. */}
        <ol className="guide-steps stagger">
          {STEPS.map((step) => (
            <li key={step.number} className="guide-step rv">
              <GlowCard className="guide-step__glow">
                <div className="guide-step__top">
                  <span className="guide-step__number">
                    <DecodeText text={step.number} />
                  </span>
                  <span className="guide-step__icon" aria-hidden="true">
                    <step.Icon size={22} strokeWidth={1.8} />
                  </span>
                </div>
                <h3 className="guide-step__title">{step.title}</h3>
                <p className="guide-step__copy">{step.copy}</p>
                {step.note ? <p className="guide-step__note">{step.note}</p> : null}
              </GlowCard>
            </li>
          ))}
        </ol>
      </section>

      <section className="guide-section rv">
        <SectionHead num="02" label="WHAT WE FIND" note="이미지는 신분증(주민등록증 · 운전면허증 · 여권)에서만 검사합니다.">
          검사 항목
        </SectionHead>
        <div className="guide-targets">
          {SCAN_TARGETS.map((group) => (
            <article key={group.title} className="guide-target">
              <h3 className="guide-target__title">{group.title}</h3>
              <ul className="guide-chips">
                {group.items.map((item) => (
                  <li key={item} className="guide-chip">{item}</li>
                ))}
              </ul>
            </article>
          ))}
          <article className="guide-target guide-target--hidden">
            <h3 className="guide-target__title">
              AI 보안 위협
              <span className="guide-target__note">사람 눈에는 보이지 않지만 AI는 읽는 것들</span>
            </h3>
            <ul className="guide-chips">
              {HIDDEN_TARGETS.map((item) => (
                <li key={item} className="guide-chip guide-chip--hidden">{item}</li>
              ))}
            </ul>
          </article>
        </div>
      </section>

      <section className="guide-section rv">
        <SectionHead num="03" label="RISK LEVELS">결과 등급</SectionHead>
        <div className="guide-levels">
          {LEVELS.map((level) => (
            <article key={level.key} className={`guide-level guide-level--${level.key}`}>
              <h3 className="guide-level__title">
                <span className="guide-level__dot" aria-hidden="true" />
                {level.label}
              </h3>
              <p className="guide-level__copy">{level.copy}</p>
            </article>
          ))}
        </div>
        <p className="guide-footnote">
          '발견없음'은 이번 검사에서 탐지된 항목이 없다는 뜻이며, 문서 전체가 안전하다는 보장은 아닙니다.
        </p>
      </section>

      <section className="guide-section rv">
        <SectionHead num="04" label="HOW TO READ">결과 확인 순서</SectionHead>
        <ol className="guide-review">
          {REVIEW_STEPS.map((item) => (
            <li key={item.step} className="guide-review__item">
              <span className="guide-review__step">{item.step}</span>
              <h3 className="guide-review__title">{item.title}</h3>
              <p className="guide-review__copy">{item.copy}</p>
            </li>
          ))}
        </ol>
      </section>

      <section className="guide-section rv">
        <SectionHead num="05" label="MASKING">마스킹 방식</SectionHead>
        <div className="guide-mask">
          <div className="guide-mask__panel">
            <span className="guide-mask__label">원본</span>
            <dl className="guide-mask__rows">
              {MASK_ROWS.map((row) => (
                <div key={row.label} className="guide-mask__row">
                  <dt className="guide-mask__key">{row.label}</dt>
                  <dd className="guide-mask__value">{row.before}</dd>
                </div>
              ))}
            </dl>
          </div>
          <div className="guide-mask__panel guide-mask__panel--after">
            <span className="guide-mask__label guide-mask__label--after">보호된 사본 (전체 마스킹 적용 시)</span>
            <dl className="guide-mask__rows">
              {MASK_ROWS.map((row) => (
                <div key={row.label} className="guide-mask__row">
                  <dt className="guide-mask__key">{row.label}</dt>
                  <dd className="guide-mask__value">
                    {row.after.map((part, index) =>
                      part.masked
                        ? <span key={index} className="guide-mask__token">{part.text}</span>
                        : <span key={index}>{part.text}</span>,
                    )}
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        </div>
        <div className="guide-mask__note">
          <p>항목마다 <b>전체 가리기</b>와 <b>부분 가리기</b>를 고를 수 있습니다.</p>
          <p>전체 가리기는 값을 <code>[유형]</code>으로 바꾸고, 부분 가리기는 가운데만 <code>*</code>로 가립니다.</p>
          <p>조직명·사업자등록번호처럼 부분만 가려도 의미가 남는 항목은 전체 가리기로 처리됩니다.</p>
        </div>
      </section>

      <section className="guide-section rv">
        <SectionHead num="06" label="DATA HANDLING" note="실제로 서버에서 일어나는 일을 그대로 적었습니다.">
          문서 처리
        </SectionHead>
        <dl className="guide-handling">
          {HANDLING.map((row) => (
            <div key={row.term} className="guide-handling__row">
              <dt className="guide-handling__term">{row.term}</dt>
              <dd className="guide-handling__desc">{row.desc}</dd>
            </div>
          ))}
        </dl>
      </section>

      <div className="guide-limit rv">
        <span className="guide-limit__icon" aria-hidden="true">
          <Info size={20} strokeWidth={1.8} />
        </span>
        <div className="guide-limit__body">
          <h2 className="guide-limit__title">검사 결과에 대해 알아두세요</h2>
          <p>DocX-ray는 문서 안의 위험 요소를 찾는 데 도움을 줍니다.</p>
          <p>다만 모든 개인정보와 숨은 지시문을 빠짐없이 찾아낸다고 보장하지는 않습니다.</p>
          <p>중요한 문서는 검사 결과와 함께 직접 한 번 더 확인해 주세요.</p>
        </div>
      </div>

      <div className="cta-card rv">
        <div>
          <b>지금 문서의 보안 상태를 확인해 보세요.</b>
          <p>업로드부터 안전한 문서 다운로드까지, DocX-ray가 도와드립니다.</p>
        </div>
        <Button onClick={goToUpload}>문서 검사 시작하기 →</Button>
      </div>

      <section className="training-guide rv" aria-labelledby="training-guide-title">
        <header className="training-guide__head">
          <p className="eyebrow">TRAINING GUIDE</p>
          <h2 id="training-guide-title" className="training-guide__title">
            <span>AI 보안 대응 훈련</span> 이용가이드
          </h2>
          <p className="training-guide__desc">
            실제와 유사한 상황에서 직접 대응하며, AI 보안 감각을 키워보세요.
          </p>
        </header>

        <ol className="training-guide__steps">
          {TRAINING_STEPS.map((step, index) => (
            <li key={step.number} className="training-guide__step">
              <div className="training-guide__item">
                <span className="training-guide__icon" aria-hidden="true">
                  <step.Icon size={32} strokeWidth={1.8} />
                </span>
                <span className="training-guide__number">STEP {step.number}</span>
                <h3 className="training-guide__step-title">{step.title}</h3>
                <p className="training-guide__copy">{step.copy}</p>
              </div>
              {index < TRAINING_STEPS.length - 1 ? (
                <ChevronRight className="training-guide__arrow" size={24} strokeWidth={1.5} aria-hidden="true" />
              ) : null}
            </li>
          ))}
        </ol>

        <div className="training-guide__cta">
          <Button size="lg" onClick={() => navigate('training')}>훈련 시작하기 →</Button>
          <p>지금, 더 안전한 나를 만들어보세요.</p>
        </div>
      </section>
    </div>
  )
}
