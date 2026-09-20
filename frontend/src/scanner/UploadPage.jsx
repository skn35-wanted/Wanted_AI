import { useEffect, useRef, useState } from 'react'
import { BookOpen, FolderClock, Handshake, MessageSquareText, Paperclip, ScanSearch, Send } from 'lucide-react'
import { api, UPLOAD_LIMITS } from '../shared/api.js'
import { AppFooter, Badge, Button, DecodeText, GlowCard, Modal, RiskBadge, SectionRail } from '../shared/components/index.js'
import { GROUPS, GROUP_ORDER, countByGroup, formatPercent, SOURCE_LABELS } from '../shared/findings.js'
import { maskedPreviewText } from '../shared/maskingRules.js'
import './scanner.css'
import './landing.css'

// 데모 샘플 한 줄 설명. sample_data/README.md의 "최소 4개 필요" 목록과 같은 뜻이다.
// 여기 없는 파일이 들어와도 화면은 형식만 보여주고 넘어간다.
const SAMPLE_NOTES = {
  '고객명단.xlsx': '이름·전화번호·주소가 줄줄이 들어간 고객 명단',
  '개발문서.md': 'API 키가 그대로 적혀 있는 개발 문서',
  '계약서.pdf': '사업자등록번호와 계좌번호가 들어간 계약서',
  '숨은명령.docx': '흰 글씨로 AI 지시문을 숨겨 둔 문서',
}

// 스캐너가 읽는 확장자. backend/scanner/scan.py의 _FILE_TYPE_BY_EXTENSION(= parse.py의 표)과 같게 둔다.
const ACCEPTED_EXTENSIONS = [
  '.pdf', '.docx', '.xlsx', '.xlsm',
  '.txt', '.md', '.csv', '.log',
  '.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp', '.tif', '.tiff',
]

const SECTIONS = [
  { id: 'intro', label: '소개' },
  { id: 'upload', label: '검사하기' },
  { id: 'share', label: '유출 위험' },
  { id: 'risk', label: '탐지 항목' },
  { id: 'flow', label: '검사 절차' },
  { id: 'privacy', label: '데이터 보호' },
]

// 성능 수치의 출처는 저장소 루트 README의 "모델" 표(합성 데이터, 5-fold 그룹 교차검증)다. 모델을 다시 학습하면 같이 고친다.
// 0.9551은 개인정보 탐지 자체가 아니라 "오탐 제거 분류기"의 PR-AUC라서 라벨을 FP FILTER로 적는다.
// 첫 화면 큰 숫자는 처음 온 사람이 3초 안에 "나한테 뭐가 좋은가"를 알 수 있는 값만 쓴다.
// 누적 검사 건수·이용자 수 같은 운영 실적은 아직 없으므로 적지 않는다.
//   0초   backend/main.py — 원본은 검사가 끝나면 바로 지운다(사본만 30분 보관)
//   18종  backend/shared/schema.py의 RiskType 중 개인정보 유형
//         (숨은 명령·숨은 텍스트와 이미지 전용 3종을 빼면 18개)
//   7종   PDF·DOCX·XLSX·TXT·MD·CSV·LOG — 이미지는 문서 형식으로 세지 않는다.
//         이미지는 신분증 3종(주민등록증·운전면허증·여권)만 검사한다. 그 밖의 사진은
//         인식률이 낮아 지원 범위에서 뺐다(2026-09-20 결정).
// detail은 카드에 마우스를 올리면(또는 키보드로 포커스하면) 뜨는 설명 — 18종은
// backend/shared/schema.py TYPE_LABELS에서 위 18개만 그대로 옮겨 적은 것이라, 유형이 늘거나
// 이름이 바뀌면 같이 고쳐야 한다.
const HERO_METRICS = [
  {
    value: '0초',
    label: '원본 보관 시간',
    detail: '업로드한 원본은 검사가 끝나는 즉시 서버에서 삭제합니다. 마스킹 사본은 30분 동안만 내려받을 수 있고, 그 뒤 자동으로 삭제됩니다.',
  },
  {
    value: '18종',
    label: '찾아내는 개인정보 유형',
    detail:
      '주민등록번호 · 여권번호 · 운전면허번호 · 외국인등록번호 · 계좌번호 · 카드번호 · API 키 · DB 접속정보 · 이메일 · 전화번호 · 사업자등록번호 · 법인등록번호 · IP 주소 · 사번 · 생년월일 · 이름 · 주소 · 조직명',
  },
  {
    value: '7종',
    label: '지원 문서 형식',
    detail:
      'PDF · DOCX · XLSX · TXT · MD · CSV · LOG. 이미지는 신분증 3종(주민등록증 · 운전면허증 · 여권)만 지원합니다.',
  },
]

// 숨은 위험 목록은 backend/scanner/parser/parse.py·detectors/hidden.py가 실제로 잡는 것만 적는다.
const HIDDEN_TRICKS = [
  '흰 배경 흰 글씨',
  '0PT · 투명 텍스트',
  'WORD 숨김 속성',
  'EXCEL VERYHIDDEN 시트',
  'PDF 페이지 밖 텍스트',
  '제로폭 · BIDI · UNICODE TAG',
  '이미지로 덮은 문장',
  '추적 삭제된 명령',
]

// "검사하기" 바로 밑, 왜 검사해야 하는지를 먼저 설득하는 자리. 문서를 보내는 네 가지 흔한 상황을 든다.
const SHARE_SCENARIOS = [
  {
    Icon: Send,
    title: '외부로 전달할 때',
    copy: (
      <>
        협력사에 견적서를 보냈는데
        <br />
        담당자의 연락처와 개인정보까지 함께 포함되어 있다면?
      </>
    ),
  },
  {
    Icon: Paperclip,
    title: '파일을 첨부할 때',
    copy: (
      <>
        메일에 문서를 첨부했는데
        <br />
        눈에 보이지 않는 정보까지 함께 전달된다면?
      </>
    ),
  },
  {
    Icon: FolderClock,
    title: '오래된 문서를 재사용할 때',
    copy: (
      <>
        기존 문서를 복사해 사용했는데
        <br />
        이전 고객의 정보가 남아 있다면?
      </>
    ),
  },
  {
    Icon: Handshake,
    title: '조직 안에서 공유할 때',
    copy: (
      <>
        업무상 필요한 사람에게 전달했는데
        <br />
        불필요한 개인정보까지 노출된다면?
      </>
    ),
  },
]

// 전문 용어(Bidi·유니코드 태그·OCR·문맥 등) 대신 실제로 벌어지는 일을 그림으로 떠올릴 수 있게 풀어 썼다.
// 무엇을 하는지는 각 설명이 가리키는 파일에 그대로 있다 — 표현만 쉽게 바꿨을 뿐 바뀐 사실은 없다.
const RISKS = [
  {
    tag: 'HIDDEN TEXT', // backend/scanner/detectors/hidden.py의 _REASONS
    title: '안 보이게 감춰진 글자도 찾아냅니다',
    copy: '흰 글씨로 쓴 문장이나, 지운 것처럼 보이지만 실제로는 문서 안에 남아 있는 내용까지 찾아냅니다.',
  },
  {
    tag: 'STRUCTURE', // 위와 같은 파일의 sheet_very_hidden·outside_page·covered_by_image
    title: '문서 안에 숨은 자리까지 확인합니다',
    copy: '엑셀에 숨겨 둔 시트나 화면 밖으로 밀려난 페이지처럼, 겉으로는 안 보이는 자리에 있는 내용까지 확인합니다.',
  },
  {
    tag: 'UNICODE', // 위와 같은 파일의 INVISIBLE_A/B/BIDI — 실제로 잡는 건 "안 보이는 문자"다(호모글리프가 아니다)
    title: '눈에 안 보이는 특수 문자도 찾아냅니다',
    copy: '화면에는 안 보이지만 실제로 존재하는 특수 문자를 찾아내, 그 안에 숨겨진 문장을 복원해 위험한 내용인지 확인합니다.',
  },
  {
    tag: 'CHECKSUM', // backend/scanner/detectors/rules.py — 체크섬까지 확인하는 네 가지 번호
    title: '숫자가 진짜 번호인지 확인합니다',
    copy: '주민등록번호나 카드번호처럼 보이는 숫자가 실제로 그 번호의 형식에 맞는지 검사합니다.',
  },
  {
    tag: 'CONTEXT', // 위와 같은 파일 — 사번은 라벨로, 계좌번호는 형식으로 구분해 서로 오탐 나지 않게 한다
    title: '숫자만 보고 넘겨짚지 않습니다',
    copy: '계좌번호와 모양이 비슷한 주문번호나 사번은 앞뒤 문장을 보고 구분해 잘못 찾는 일을 줄입니다.',
  },
  {
    tag: 'IMAGE · OCR', // backend/scanner/detectors/text_ocr.py — EasyOCR로 읽은 글자를 같은 검사 파이프라인에 그대로 태운다
    title: '사진 속 글자도 놓치지 않습니다',
    copy: '스캔한 문서나 사진처럼 글자가 그림으로 되어 있어도 내용을 읽어내어 똑같이 검사합니다.',
  },
]

const STEPS = [
  {
    title: '문서를 올립니다',
    copy: (
      <>
        검사할 파일을 업로드하세요.
        <br />
        다양한 문서 형식을 지원합니다.
      </>
    ),
  },
  {
    title: 'AI가 위험을 찾습니다',
    copy: (
      <>
        개인정보부터 문서 속 숨겨진 정보까지
        <br />
        AI가 문서 전체를 분석합니다.
      </>
    ),
  },
  {
    title: '안전하게 확인합니다',
    copy: (
      <>
        발견된 위험 정보를 확인하고
        <br />
        필요한 정보는 자동으로 마스킹해 안전하게 활용하세요.
      </>
    ),
  },
]

const PRIVACY = [
  { tag: 'DELETE ON FINALLY', copy: '업로드 원본은 검사 성공·실패와 관계없이 즉시 삭제합니다.' },
  { tag: 'TTL 30 MIN', copy: '마스킹 사본은 임시 경로에 두고 기본 30분 뒤 삭제합니다.' },
  { tag: 'NO RAW VALUES', copy: '원문 대화와 탐지된 개인정보 값은 DB에 저장하지 않습니다.' },
  { tag: 'SYNTHETIC ONLY', copy: '학습·테스트 데이터는 실제 개인정보 없이 합성 생성기로 만듭니다.' },
]

// 텍스트 붙여넣기 상자의 최대 글자 수. 서버(backend/main.py의 MAX_TEXT_LENGTH)는 100,000자까지
// 받아주지만, 화면에서는 더 짧게 제한한다 — 이보다 길면 422가 아니라 여기서 막힌다.
const MAX_TEXT_LENGTH = 2000

function extensionOf(name) {
  const dot = name.lastIndexOf('.')
  return dot >= 0 ? name.slice(dot).toLowerCase() : ''
}

// 탐지된 값은 붙여 넣은 본인의 글이지만, 목록이 길어지지 않게 앞부분만 보여준다.
function shorten(value = '', limit = 48) {
  const chars = Array.from(value)
  return chars.length > limit ? `${chars.slice(0, limit).join('')}…` : value
}

// 같은 유형 + 같은 값의 탐지를 하나로 묶어 "이름 홍길동 · 3건"처럼 건수로 보여준다.
function groupDuplicateFindings(findings) {
  const byKey = new Map()
  for (const finding of findings) {
    const key = `${finding.type}::${finding.text}`
    const existing = byKey.get(key)
    if (existing) {
      existing.count += 1
      existing.maxConfidence = Math.max(existing.maxConfidence, finding.confidence)
    } else {
      byKey.set(key, {
        key,
        label: finding.label,
        text: finding.text,
        type: finding.type,
        source: finding.source,
        count: 1,
        maxConfidence: finding.confidence,
      })
    }
  }
  return [...byKey.values()]
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`
  const megabytes = bytes / 1024 / 1024
  return `${Number.isInteger(megabytes) ? megabytes : megabytes.toFixed(1)} MB`
}

function scrollToSection(id, block = 'start') {
  const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
  document.getElementById(id)?.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block })
}

// 첫 화면(랜딩). 소개 → 숨은 위험 → 작동 방식 → 성능 → 프라이버시 → 업로드 순서다.
// 업로드 상자는 맨 아래 CTA 자리에 있고, 위의 "무료로 스캔 시작"이 그곳으로 데려간다.
// 업로드 상자의 주 버튼(CTA)은 상태에 따라 바뀐다.
//   파일 고르기 전  "파일 선택하기"          — 업로드 영역이 크게 보인다.
//   파일 고른 뒤    "AI 보안 검사 시작"      — 업로드 영역은 "파일 추가하기" 한 줄로 줄어든다.
// 샘플 문서 체험은 파일이 없는 사람(심사위원 시연 등)을 위한 것이다. 고르는 자리는 업로드 상자 아래 한 곳뿐이고,
// 소개의 "샘플로 체험하기"는 검사를 바로 시작하지 않고 그 자리로 데려다만 준다 — 무엇을 검사할지 먼저 보게 한다.
export default function UploadPage({ onScan, error, busy, navigate }) {
  const inputRef = useRef(null)
  const sampleRef = useRef(null)
  const backdropRef = useRef(null)
  const glowRef = useRef(null)
  const scanFrameRef = useRef(null)
  const [files, setFiles] = useState([])
  const [dragging, setDragging] = useState(false)
  const [problems, setProblems] = useState([])
  // 텍스트 붙여넣기 검사 — 파일 없이 문장만 검사한다(POST /scan/text). 붙여 넣은 글은 메모리에만 두고
  // 브라우저 저장소에 남기지 않는다(검사 결과와 같은 기준).
  const [mode, setMode] = useState('file') // 'file' | 'text'
  const [draft, setDraft] = useState('')
  const [scannedText, setScannedText] = useState('')
  const [textResult, setTextResult] = useState(null)
  const [textScanning, setTextScanning] = useState(false)
  const [textError, setTextError] = useState('')
  const [textTypeFilter, setTextTypeFilter] = useState('') // '' = 첫 유형(아직 안 골랐을 때). 묶음 표(아래)만 걸러 보여준다.
  const [textTablePage, setTextTablePage] = useState(1) // 묶음 표 페이지 — 10건 넘으면 나눠 보여준다.
  const [textMaskMode, setTextMaskMode] = useState('full') // 'full' | 'standard' — MaskPage.jsx와 같은 두 값
  const [copied, setCopied] = useState(false)
  const [confirmClearOpen, setConfirmClearOpen] = useState(false)
  const [toast, setToast] = useState('')
  const toastTimerRef = useRef(null)
  // 체험용 데모 문서. 목록만 따로 받아서(검사 없이) 고를 수 있게 보여준다.
  const [samples, setSamples] = useState([])
  const [pickedSamples, setPickedSamples] = useState([])
  const hasFiles = files.length > 0

  useEffect(() => () => clearTimeout(toastTimerRef.current), [])

  useEffect(() => {
    let cancelled = false
    api
      .sampleList()
      .then(({ samples: list = [] }) => {
        if (cancelled) return
        setSamples(list)
        setPickedSamples([]) // 처음엔 아무것도 안 고른 상태 — 직접 골라야 한다
      })
      .catch(() => {
        // 목록을 못 받으면 고르는 화면을 숨기고 예전처럼 "전체 샘플" 버튼 하나만 둔다.
        if (!cancelled) setSamples([])
      })
    return () => {
      cancelled = true
    }
  }, [])

  const toggleSample = (filename) =>
    setPickedSamples((picked) =>
      picked.includes(filename) ? picked.filter((name) => name !== filename) : [...picked, filename],
    )

  // 검사가 실패해 이 화면으로 돌아오면 오류 문구가 있는 업로드 상자를 보여준다(맨 아래라 안 보일 수 있다).
  useEffect(() => {
    if (error) scrollToSection('upload', 'center')
  }, [error])

  // 스캔 애니메이션(iframe)은 다른 문서라 이 페이지의 격자·빛 배경 CSS를 그대로 쓸 수 없다.
  // 격자 원점(.landing__backdrop)과 위쪽 빛(.landing__glow) 대비 iframe의 위치를 계산해
  // postMessage로 넘겨서, iframe 안쪽에 같은 격자·빛을 같은 자리에 그리게 한다 — 격자 선만
  // 맞추고 빛 얼룩을 안 그리면 그 밝기 차이만큼 경계가 도로 티가 난다. src를 바꿔 새로
  // 불러오면 애니메이션이 처음부터 다시 부팅되니 절대 reload하지 않고 메시지로만 갱신한다.
  useEffect(() => {
    function sendGridOffset() {
      const backdrop = backdropRef.current
      const glow = glowRef.current
      const frame = scanFrameRef.current
      const win = frame?.contentWindow
      if (!backdrop || !win) return
      const backdropRect = backdrop.getBoundingClientRect()
      const frameRect = frame.getBoundingClientRect()
      // 격자는 안쪽 body를 기준으로 "패턴의 원점을 어디로 밀지"를 지정하는 값이라, 격자 원점이
      // iframe보다 화면 왼쪽/위쪽에 있을수록(=frameRect가 backdropRect보다 오른쪽/아래일수록)
      // 안쪽 패턴은 반대 방향으로 밀어야 두 격자의 선이 같은 화면 좌표에서 만난다.
      const x = backdropRect.left - frameRect.left
      const y = backdropRect.top - frameRect.top
      // 세로 페이드는 반대로 "iframe이 격자 원점에서 얼마나 아래에 있는지"가 필요해 부호가 다르다.
      const frameTopWithinBackdrop = frameRect.top - backdropRect.top
      const fadeEnd = backdropRect.height * 0.7
      const centerY = frameTopWithinBackdrop + frameRect.height / 2
      const opacity = fadeEnd <= 0 ? 0 : Math.max(0, Math.min(1, 1 - centerY / fadeEnd))
      let glowPayload = null
      if (glow) {
        const glowRect = glow.getBoundingClientRect()
        glowPayload = {
          cx: glowRect.left + glowRect.width / 2 - frameRect.left,
          cy: glowRect.top + glowRect.height / 2 - frameRect.top,
          w: glowRect.width,
          h: glowRect.height,
        }
      }
      win.postMessage({ type: 'scan-grid:offset', x, y, opacity, glow: glowPayload }, '*')
    }
    sendGridOffset()
    function onMessage(e) {
      if (e.data?.type === 'scan-grid:request') sendGridOffset()
    }
    window.addEventListener('resize', sendGridOffset)
    window.addEventListener('message', onMessage)
    return () => {
      window.removeEventListener('resize', sendGridOffset)
      window.removeEventListener('message', onMessage)
    }
  }, [])

  function openPicker() {
    if (!busy) inputRef.current?.click()
  }


  // 소개의 "샘플로 체험하기" — 검사를 시작하지 않고 고르는 자리로 내려간다.
  // 목차로 이동할 때와 같은 테두리를 잠깐 띄워, 긴 화면에서 어디로 왔는지 보이게 한다.
  function goToSamples() {
    const target = sampleRef.current
    if (!target) return
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    // 포커스를 먼저 옮긴다. 부드러운 스크롤이 도는 중에 focus()를 부르면 브라우저가
    // 그 스크롤을 취소해 버려서 화면이 맨 위에 그대로 남는다(실측).
    target.querySelector('input, button')?.focus({ preventScroll: true })
    target.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'center' })
    target.classList.remove('section-target')
    void target.offsetWidth // 연달아 눌러도 테두리가 처음부터 다시 돌게
    target.classList.add('section-target')
    setTimeout(() => target.classList.remove('section-target'), 1600)
  }

  function goToUpload() {
    scrollToSection('upload')
    document.querySelector('#upload .dropzone .btn')?.focus({ preventScroll: true })
  }

  function addFiles(fileList) {
    const next = [...files]
    const found = []
    for (const file of Array.from(fileList)) {
      if (!ACCEPTED_EXTENSIONS.includes(extensionOf(file.name))) {
        found.push(`${file.name}: 지원하지 않는 형식입니다.`)
        continue
      }
      if (file.size > UPLOAD_LIMITS.maxFileBytes) {
        found.push(`${file.name}: 파일당 ${formatBytes(UPLOAD_LIMITS.maxFileBytes)}까지 올릴 수 있습니다.`)
        continue
      }
      if (next.some((picked) => picked.name === file.name && picked.size === file.size)) continue
      if (next.length >= UPLOAD_LIMITS.maxFiles) {
        found.push(`한 번에 ${UPLOAD_LIMITS.maxFiles}개까지 올릴 수 있습니다.`)
        break
      }
      next.push(file)
    }
    setFiles(next)
    setProblems(found)
  }

  async function runTextScan() {
    const text = draft.trim()
    if (!text || textScanning) return
    setTextScanning(true)
    setTextError('')
    setTextResult(null)
    setCopied(false)
    setTextTypeFilter('')
    setTextTablePage(1)
    setTextMaskMode('full')
    try {
      // finding.start/end는 서버에 보낸 이 문자열(trim 후) 기준이라, 하이라이트가 어긋나지
      // 않게 결과와 같은 스냅샷을 따로 들고 있는다 — draft는 이후 사용자가 계속 고칠 수 있다.
      setScannedText(text)
      setTextResult(await api.scanText(text))
    } catch (err) {
      setTextError(err.message)
    } finally {
      setTextScanning(false)
    }
  }

  function showToast(message) {
    setToast(message)
    clearTimeout(toastTimerRef.current)
    toastTimerRef.current = setTimeout(() => setToast(''), 2200)
  }

  function clearText() {
    setDraft('')
    setScannedText('')
    setTextResult(null)
    setTextError('')
    setCopied(false)
    setTextTypeFilter('')
    setTextTablePage(1)
    setTextMaskMode('full')
    setConfirmClearOpen(false)
  }

  async function copyMasked() {
    try {
      await navigator.clipboard.writeText(textMaskedPreview)
      setCopied(true)
      showToast('복사가 완료되었습니다')
    } catch {
      setTextError('브라우저가 복사를 막았습니다. 아래 상자에서 직접 선택해 복사해 주세요.')
    }
  }

  const textCounts = textResult ? countByGroup(textResult.findings) : null
  // 드롭다운 목록 — 이번 결과에 실제로 나온 유형만, 처음 나온 순서대로. "전체 유형" 선택지는 없고
  // 항상 유형 하나를 보여준다 — 고른 적이 없으면 첫 번째 유형이 기본이다.
  const textTypeOptions = textResult
    ? [...new Map(textResult.findings.map((f) => [f.type, f.label])).entries()].map(([type, label]) => ({
        type,
        label,
      }))
    : []
  const textEffectiveTypeFilter = textTypeFilter || textTypeOptions[0]?.type || ''
  const textGroupedRows = textResult
    ? groupDuplicateFindings(textResult.findings).filter((group) => group.type === textEffectiveTypeFilter)
    : []
  // 묶음 표 페이지 나누기 — 한 유형에 10건 넘게 나오면 10개씩 잘라 보여준다.
  const TEXT_TABLE_PAGE_SIZE = 10
  const textTotalPages = Math.max(1, Math.ceil(textGroupedRows.length / TEXT_TABLE_PAGE_SIZE))
  const textCurrentPage = Math.min(textTablePage, textTotalPages)
  const textPagedRows = textGroupedRows.slice(
    (textCurrentPage - 1) * TEXT_TABLE_PAGE_SIZE,
    textCurrentPage * TEXT_TABLE_PAGE_SIZE,
  )
  // 전체([유형])/부분(박**) 마스킹 미리보기 — 서버를 다시 부르지 않고 findings.js·maskingRules.js의
  // 규칙으로 화면에서 바로 계산한다(파일 검사 결과 화면의 선택 마스킹과 같은 규칙).
  const textMaskedPreview =
    textResult && textResult.findings.length > 0
      ? maskedPreviewText(
          scannedText,
          textResult.findings,
          Object.fromEntries(textResult.findings.map((f) => [f.id, textMaskMode])),
        )
      : textResult?.masked_text ?? ''
  const messages = [...problems, ...(error ? [error] : [])]

  return (
    <div className="landing">
      <div className="landing__backdrop" aria-hidden="true" ref={backdropRef}>
        <div className="landing__grid" />
        <div className="landing__glow" ref={glowRef} />
      </div>
      <SectionRail sections={SECTIONS} />

      <section id="intro" className="container landing-hero">
        <div className="landing-hero__copy rv">
          <Badge>DOCUMENT X-RAY SCANNER</Badge>
          <h1 className="landing-hero__title">
            문서를 열기 전에,
            <br />
            <span className="landing-glow">위험</span>부터 찾습니다.
          </h1>
          <p className="landing-hero__lead">
            개인정보부터 문서 속 숨은 AI 명령어까지.
            <br />
            DocX-ray가 문서를 스캔하고, 놓치기 쉬운 위험 요소를 찾아냅니다.
          </p>
          <div className="landing-actions">
            <Button size="lg" onClick={goToUpload}>
              무료로 스캔 시작
            </Button>
            <Button size="lg" variant="secondary" disabled={busy} onClick={goToSamples}>
              샘플로 체험하기
            </Button>
          </div>
          <dl className="landing-metrics">
            {HERO_METRICS.map((metric) => {
              const tooltipId = `hero-metric-tip-${metric.label}`
              return (
                <div key={metric.label} className="landing-metric" tabIndex={0} aria-describedby={tooltipId}>
                  <dt>{metric.label}</dt>
                  <dd>
                    <DecodeText text={metric.value} />
                  </dd>
                  <span id={tooltipId} role="tooltip" className="landing-metric__tooltip">
                    {metric.detail}
                  </span>
                </div>
              )
            })}
          </dl>
          <p className="landing-metrics__note">
            원본은 검사가 끝나는 즉시 지웁니다. 마스킹 사본도 30분 뒤 자동 삭제됩니다.
          </p>
        </div>
        {/* 클로드 디자인에서 만든 스캔 애니메이션. 원본 HTML을 그대로 띄운다.
            파일은 frontend/public/scan-animation/ 에 있고, 디자인을 다시 만들면 그 폴더만 갈아 끼우면 된다. */}
        <iframe
          ref={scanFrameRef}
          className="scan-animation"
          src="/scan-animation/index.html"
          title="문서를 훑어 개인정보를 찾아내는 스캔 장면"
        />
      </section>

      <div className="container landing-cta-wrap">
        <section id="upload" className="landing-cta rv" aria-labelledby="upload-title">
          <i className="landing-cta__glow" aria-hidden="true" />
          <div className="landing-cta__inner">
            <h2 id="upload-title" className="landing-cta__title">
              보내기 전에, 한 번 확인해 보세요.
            </h2>
            <p className="landing-cta__lead">
              문서를 끌어다 놓으면 개인정보와 숨은 AI 명령을 찾아,
              <br />
              형식을 지킨 마스킹 사본으로 돌려드립니다.
            </p>

            <div className="dropzone-card">
              {/* 파일을 올리거나, 문장을 붙여 넣어 바로 검사한다 */}
              <div className="tabs" role="tablist" aria-label="검사 방법">
                <button
                  type="button"
                  role="tab"
                  className="tabs__tab"
                  aria-selected={mode === 'file'}
                  onClick={() => setMode('file')}
                >
                  파일 업로드
                </button>
                <button
                  type="button"
                  role="tab"
                  className="tabs__tab"
                  aria-selected={mode === 'text'}
                  onClick={() => setMode('text')}
                >
                  텍스트 붙여넣기
                </button>
              </div>

              {mode === 'text' && (
                <div className="text-scan">
                  <label htmlFor="text-scan-input" className="visually-hidden">
                    검사할 텍스트
                  </label>
                  <textarea
                    id="text-scan-input"
                    className="text-scan__input"
                    value={draft}
                    maxLength={MAX_TEXT_LENGTH}
                    placeholder="메일 초안, 메시지, 표에서 복사한 내용을 붙여 넣으세요. 개인정보와 숨은 AI 명령을 바로 찾습니다."
                    onChange={(event) => setDraft(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' && (event.ctrlKey || event.metaKey)) runTextScan()
                    }}
                  />

                  <div className="text-scan__row">
                    <span className="text-scan__count">
                      {draft.length.toLocaleString()} / {MAX_TEXT_LENGTH.toLocaleString()}자
                    </span>
                    <span className="row">
                      {draft && (
                        <Button variant="ghost" size="sm" disabled={textScanning} onClick={() => setConfirmClearOpen(true)}>
                          전체 삭제
                        </Button>
                      )}
                      <Button disabled={textScanning || !draft.trim()} onClick={runTextScan}>
                        {textScanning ? '검사 중…' : '텍스트 검사하기'}
                      </Button>
                    </span>
                  </div>

                  {textError && (
                    <p className="alert alert--error" role="alert">
                      {textError}
                    </p>
                  )}

                  {textResult && (
                    <div className="text-scan__result" aria-live="polite">
                      {textResult.findings.length === 0 ? (
                        <p className="text-scan__clean">찾은 개인정보가 없습니다. 그래도 보내기 전에 한 번 더 읽어 보세요.</p>
                      ) : (
                        <>
                          <div className="text-scan__masked">
                            <p className="text-scan__masked-head">
                              <span>마스킹이 완료되었습니다.</span>
                            </p>

                            {/* 전체([유형])/부분(박**) 마스킹 전환 — MaskPage.jsx(파일 검사 결과)의
                                "전체 마스킹"/"선택 마스킹" 탭과 같은 모양을 쓴다. */}
                            <div className="tabs tabs--compact" role="tablist" aria-label="마스킹 방식">
                              <button
                                type="button"
                                role="tab"
                                aria-selected={textMaskMode === 'full'}
                                className="tabs__tab"
                                onClick={() => {
                                  setTextMaskMode('full')
                                  setCopied(false)
                                }}
                              >
                                전체 마스킹
                              </button>
                              <button
                                type="button"
                                role="tab"
                                aria-selected={textMaskMode === 'standard'}
                                className="tabs__tab"
                                onClick={() => {
                                  setTextMaskMode('standard')
                                  setCopied(false)
                                }}
                              >
                                부분 마스킹
                              </button>
                            </div>

                            <p className="text-scan__masked-body">{textMaskedPreview}</p>
                            <div className="text-scan__masked-actions">
                              <Button variant="secondary" size="sm" onClick={copyMasked}>
                                {copied ? '복사완료' : '복사하기'}
                              </Button>
                            </div>
                          </div>

                          {/* 같은 값이 여러 번 나오면(이름이 반복되는 경우 등) 하나로 묶어 건수로 보여준다.
                              유형이 여러 번 겹쳐 읽기 어려울 수 있어 드롭다운으로 한 유형만 골라 본다
                              ("전체 유형"은 없다 — 목록이 길면 다 보여주는 쪽이 오히려 더 안 읽힌다). */}
                          <div className="text-scan__toolbar-row">
                            <div className="text-scan__group-toolbar">
                              <label htmlFor="text-scan-type-filter" className="text-scan__group-toolbar-label">
                                유형별 보기
                              </label>
                              <select
                                id="text-scan-type-filter"
                                className="select"
                                value={textEffectiveTypeFilter}
                                onChange={(event) => {
                                  setTextTypeFilter(event.target.value)
                                  setTextTablePage(1)
                                }}
                              >
                                {textTypeOptions.map((option) => (
                                  <option key={option.type} value={option.type}>
                                    {option.label}
                                  </option>
                                ))}
                              </select>
                            </div>

                            <div className="text-scan__summary">
                              <RiskBadge level={textResult.level} score={textResult.risk_score} />
                              <ul className="text-scan__counts">
                                {GROUP_ORDER.filter((key) => textCounts[key] > 0).map((key) => (
                                  <li key={key}>
                                    {GROUPS[key].label} <b>{textCounts[key]}건</b>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          </div>

                          <div className="text-scan__group-table-wrap">
                            <table className="text-scan__group-table">
                              <thead>
                                <tr>
                                  <th scope="col">유형</th>
                                  <th scope="col">값</th>
                                  <th scope="col">건수</th>
                                  <th scope="col">확신도</th>
                                  <th scope="col">근거</th>
                                </tr>
                              </thead>
                              <tbody>
                                {textPagedRows.map((group) => (
                                  <tr key={group.key}>
                                    <td>{group.label}</td>
                                    <td>{shorten(group.text, 24)}</td>
                                    <td>{group.count}건</td>
                                    <td>{formatPercent(group.maxConfidence)}</td>
                                    <td>{SOURCE_LABELS[group.source] ?? group.source}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                            {textGroupedRows.length === 0 && (
                              <p className="text-scan__group-empty">이 유형에 해당하는 항목이 없습니다.</p>
                            )}
                          </div>

                          {/* 10건 넘으면 페이지 인디케이터. 유형을 바꾸면 1페이지로 되돌아간다(위 select onChange). */}
                          {textTotalPages > 1 && (
                            <nav className="text-scan__pagination" aria-label="묶음 표 페이지">
                              {Array.from({ length: textTotalPages }, (_, index) => index + 1).map((page) => (
                                <button
                                  key={page}
                                  type="button"
                                  className="text-scan__page-btn"
                                  aria-current={page === textCurrentPage ? 'true' : undefined}
                                  onClick={() => setTextTablePage(page)}
                                >
                                  {page}
                                </button>
                              ))}
                            </nav>
                          )}

                          {textResult.filtered_count > 0 && (
                            <p className="text-scan__filtered">
                              형태는 비슷하지만 개인정보가 아니라고 판단해 {textResult.filtered_count}건은 제외했습니다.
                            </p>
                          )}
                        </>
                      )}
                    </div>
                  )}
                </div>
              )}

              {mode === 'file' && (
                <>
              {/* 파일 선택 창은 버튼으로 연다. 영역 빈 곳을 눌러도 열리지만 키보드 사용자는 버튼을 쓴다. */}
              <div
                className={`dropzone${hasFiles ? ' dropzone--compact' : ''}${dragging ? ' is-dragging' : ''}`}
                onClick={(event) => {
                  if (!event.target.closest('button')) openPicker()
                }}
                onDragOver={(event) => {
                  event.preventDefault()
                  setDragging(true)
                }}
                onDragLeave={() => setDragging(false)}
                onDrop={(event) => {
                  event.preventDefault()
                  setDragging(false)
                  if (!busy) addFiles(event.dataTransfer.files)
                }}
              >
                <input
                  ref={inputRef}
                  type="file"
                  multiple
                  accept={ACCEPTED_EXTENSIONS.join(',')}
                  className="visually-hidden"
                  tabIndex={-1}
                  aria-hidden="true"
                  disabled={busy}
                  onChange={(event) => {
                    addFiles(event.target.files)
                    event.target.value = '' // 같은 파일을 빼고 다시 고를 수 있게
                  }}
                />

                {hasFiles ? (
                  <>
                    <p className="dropzone__compact-text">파일을 더 업로드하려면 이곳으로 끌어오세요</p>
                    <Button variant="secondary" size="sm" disabled={busy} onClick={openPicker}>
                      파일 추가하기
                    </Button>
                  </>
                ) : (
                  <>
                    <span className="dropzone__icon" aria-hidden="true">
                      ⌑
                    </span>
                    <h3 className="dropzone__title">문서를 업로드하세요</h3>
                    <p className="dropzone__hint">
                      PDF · Word · Excel · 텍스트 · 신분증 이미지 (최대 {UPLOAD_LIMITS.maxFiles}개, 파일당{' '}
                      {formatBytes(UPLOAD_LIMITS.maxFileBytes)})
                    </p>
                    <Button size="lg" disabled={busy} onClick={openPicker}>
                      파일 업로드하여 스캔
                    </Button>
                    <p className="dropzone__drop">또는 파일을 이곳으로 끌어오세요</p>
                  </>
                )}
              </div>

              {messages.length > 0 && (
                <p className="alert alert--error" role="alert">
                  {messages.map((message) => (
                    <span key={message} className="alert__line">
                      {message}
                    </span>
                  ))}
                </p>
              )}

              {hasFiles && (
                <>
                  <ul className="file-list" aria-label="선택한 파일">
                    {files.map((file) => (
                      <li key={`${file.name}-${file.size}`} className="file-list__item">
                        <span className="file-list__icon" aria-hidden="true">
                          ⌑
                        </span>
                        <span className="file-list__info">
                          <span className="file-list__name">{file.name}</span>
                          <span className="file-list__size">{formatBytes(file.size)}</span>
                        </span>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="file-list__remove"
                          disabled={busy}
                          aria-label={`${file.name} 삭제`}
                          onClick={() => setFiles((prev) => prev.filter((picked) => picked !== file))}
                        >
                          삭제
                        </Button>
                      </li>
                    ))}
                  </ul>
                  <Button size="lg" block disabled={busy} onClick={() => onScan('files', files)}>
                    AI 보안 검사 시작{files.length > 1 ? ` (${files.length}개)` : ''} →
                  </Button>
                </>
              )}

                </>
              )}

              <p className="dropzone-card__note">
                {mode === 'text'
                  ? '붙여 넣은 텍스트는 검사에만 쓰고 서버에 저장하지 않습니다. 사본 파일도 만들지 않습니다.'
                  : '업로드된 원본은 검사 완료 즉시 삭제되며, 마스킹 사본은 30분간 다운로드할 수 있습니다.'}
              </p>
              {mode !== 'text' && (
                <p className="dropzone-card__note">
                  고해상도 이미지는 빠르고 안정적인 검사를 위해 장변 1,400px 기준으로 축소해 분석합니다.
                  OCR이 필요한 PDF(스캔본)는 처음 8쪽까지 분석합니다. 텍스트 파일이 100KB를 넘으면
                  전화번호·이메일·주민등록번호 등은 그대로 검사하되 사람·회사명 탐지는 생략합니다.
                </p>
              )}

              <div className="sample-cta" ref={sampleRef}>
                <p className="sample-cta__text">문서가 없어도 바로 체험해 보기</p>
                {samples.length === 0 ? (
                  <Button variant="ghost" disabled={busy} onClick={() => onScan('samples')}>
                    샘플 문서로 검사해보기 →
                  </Button>
                ) : (
                  <>
                    <ul className="sample-pick">
                      {samples.map((sample) => (
                        <li key={sample.filename}>
                          <label className="sample-pick__item">
                            <input
                              type="checkbox"
                              checked={pickedSamples.includes(sample.filename)}
                              onChange={() => toggleSample(sample.filename)}
                              disabled={busy}
                            />
                            <span className="sample-pick__body">
                              <b className="sample-pick__name">{sample.filename}</b>
                              <span className="sample-pick__note">
                                {SAMPLE_NOTES[sample.filename] ?? sample.file_type}
                              </span>
                            </span>
                          </label>
                        </li>
                      ))}
                    </ul>
                    <Button
                      variant="ghost"
                      disabled={busy || pickedSamples.length === 0}
                      onClick={() => onScan('samples', pickedSamples)}
                    >
                      {pickedSamples.length === 0
                        ? '문서를 하나 이상 고르세요'
                        : `선택한 ${pickedSamples.length}개로 검사해보기 →`}
                    </Button>
                  </>
                )}
              </div>
            </div>

            <p className="landing-cta__foot">NO ACCOUNT · ORIGINAL DELETED IMMEDIATELY</p>
          </div>
          <i className="landing-cta__sweep" aria-hidden="true" />
        </section>
      </div>

      <div className="landing-marquee">
        <div className="landing-marquee__track">
          <ul className="landing-marquee__group" aria-label="검사하는 숨은 위험">
            {HIDDEN_TRICKS.map((trick) => (
              <li key={trick}>{trick}</li>
            ))}
          </ul>
          {/* 끊김 없이 흐르게 같은 목록을 한 번 더 붙인다. 화면 읽기 프로그램에는 한 번만 읽힌다. */}
          <ul className="landing-marquee__group" aria-hidden="true">
            {HIDDEN_TRICKS.map((trick) => (
              <li key={trick}>{trick}</li>
            ))}
          </ul>
        </div>
      </div>

      <section id="share" className="container landing-section">
        <div className="rv">
          <h2 className="landing-h2">
            문서가 넘어가는 순간,
            <br />
            위험도 함께 넘어갑니다
          </h2>
          <p className="landing-lead">
            업무를 위해 공유하는 문서에는
            <br />
            의도하지 않은 개인정보까지 함께 포함될 수 있습니다.
          </p>
        </div>
        <ul className="landing-cards landing-cards--scenario stagger">
          {SHARE_SCENARIOS.map((item) => (
            <GlowCard as="li" key={item.title} className="landing-card rv">
              <span className="landing-card__icon" aria-hidden="true">
                <item.Icon size={22} strokeWidth={1.8} />
              </span>
              <h3 className="landing-card__title">{item.title}</h3>
              <p className="landing-card__copy">{item.copy}</p>
            </GlowCard>
          ))}
        </ul>
      </section>

      <section id="risk" className="container landing-section">
        <div className="rv">
          <h2 className="landing-h2">
            문서는 멀쩡해 보여도
            <br />
            숨겨진 위험은 존재할 수 있습니다.
          </h2>
          <p className="landing-lead">
            일반적인 검사는 눈에 보이는 텍스트만 확인합니다.
            <br />
            DocX-ray는 문서의 구조부터 숨겨진 데이터, 신분증 이미지 속 정보까지 살펴봅니다.
          </p>
        </div>
        <ul className="landing-cards landing-cards--risk stagger">
          {RISKS.map((risk) => (
            <GlowCard as="li" key={risk.tag} className="landing-card rv">
              <p className="landing-card__tag">{risk.tag}</p>
              <h3 className="landing-card__title">{risk.title}</h3>
              <p className="landing-card__copy">{risk.copy}</p>
            </GlowCard>
          ))}
        </ul>
      </section>

      <section id="flow" className="landing-band">
        <div className="container">
          <div className="rv">
            <h2 className="landing-h2">한 번의 검사로, 문서 속 위험을 찾아냅니다</h2>
          </div>
          <ol className="landing-steps stagger">
            {STEPS.map((step, index) => (
              <GlowCard
                as="li"
                key={step.title}
                className={`landing-step rv${index === 1 ? ' landing-step--active' : ''}`}
              >
                <span className="landing-step__num" aria-hidden="true">
                  {String(index + 1).padStart(2, '0')}
                </span>
                <h3 className="landing-step__title">{step.title}</h3>
                <p className="landing-step__copy">{step.copy}</p>
              </GlowCard>
            ))}
          </ol>
        </div>
      </section>

      <section id="privacy" className="landing-band landing-band--plain">
        <div className="container">
          <div className="rv">
            <h2 className="landing-h2">찾기 위해 보관하지 않습니다</h2>
          </div>
          <ul className="landing-cards landing-cards--privacy stagger">
            {PRIVACY.map((item) => (
              <GlowCard as="li" key={item.tag} className="landing-card rv">
                <p className="landing-card__tag">{item.tag}</p>
                <p className="landing-card__copy landing-card__copy--bright">{item.copy}</p>
              </GlowCard>
            ))}
          </ul>
        </div>
      </section>

      {/* 전환 띠 — 바닥글 바로 위에서 다음 행동 세 가지를 고르게 한다 */}
      <section className="landing-outro rv" aria-labelledby="outro-title">
        <div className="landing-outro__center">
          <h2 id="outro-title" className="landing-outro__title">
            <span className="landing-outro__accent">개인에서 조직으로,</span> 더 안전한 문서 환경을 만듭니다.
          </h2>
          <p className="landing-outro__lead">
            개인·직장인의 문서 보안에서 시작해, 팀과 회사가 함께 쓰는 보안 습관까지 넓혀 갑니다.
          </p>
          <div className="landing-outro__actions">
            <button type="button" className="landing-pill" onClick={() => scrollToSection('upload')}>
              <span aria-hidden="true">
                <ScanSearch size={18} strokeWidth={2} />
              </span>
              문서 보안 검사
            </button>
            <button type="button" className="landing-pill" onClick={() => navigate('training')}>
              <span aria-hidden="true">
                <MessageSquareText size={18} strokeWidth={2} />
              </span>
              사기 대응 훈련
            </button>
            <button type="button" className="landing-pill" onClick={() => navigate('guide')}>
              <span aria-hidden="true">
                <BookOpen size={18} strokeWidth={2} />
              </span>
              이용 가이드
            </button>
          </div>
        </div>
      </section>

      {/* 바닥글 — 링크는 이 앱 안에서 실제로 동작하는 것만 둔다(없는 페이지로 가는 링크는 누르면 바로 드러난다) */}
      <AppFooter navigate={navigate} onScan={onScan} busy={busy} />

      <Modal
        open={confirmClearOpen}
        title="입력한 내용을 전체 삭제하시겠습니까?"
        onClose={() => setConfirmClearOpen(false)}
        actions={
          <>
            <Button variant="ghost" onClick={() => setConfirmClearOpen(false)}>
              취소
            </Button>
            <Button variant="danger" onClick={clearText}>
              전체 삭제
            </Button>
          </>
        }
      >
        <p>전체 삭제 시 복구할 수 없으며, 붙여 넣은 텍스트와 검사 결과가 함께 삭제됩니다.</p>
      </Modal>

      {/* 복사 완료 토스트. 2.2초 뒤 스스로 사라진다(showToast). */}
      <div className={`toast${toast ? ' toast--visible' : ''}`} role="status" aria-live="polite">
        {toast}
      </div>
    </div>
  )
}
