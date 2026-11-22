import { useEffect, useState, type ChangeEvent, type FormEvent } from 'react'
import './App.css'

const MAX_MESSAGE_LENGTH = 2000
const MAX_EXTRACTED_MESSAGE_LENGTH = 5000
const MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024
const SCAN_HISTORY_PAGE_SIZE = 8
const CURRENT_YEAR = new Date().getFullYear()
const API_BASE_URL = (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000')
  .trim()
  .replace(/\/+$/, '')

const IMAGE_MIME_TYPES: Record<string, string> = {
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  webp: 'image/webp',
}

type AnalyzeMessageResponse = {
  predicted_label: 'spam' | 'legitimate'
  risk_level: 'elevated' | 'unconfirmed'
  model_probability: number
  explanation: string
  warning_signs: string[]
  recommendations: string[]
}

type AnalyzeURLResponse = {
  risk_level: 'unverified' | 'caution'
  risk_indicators: string[]
  explanation: string
  warning_signs: string[]
  recommendations: string[]
}

type ScanType = 'message' | 'url' | 'screenshot'
type RiskLevel = 'elevated' | 'unconfirmed' | 'caution' | 'unverified'

type ScanHistoryItem = {
  scan_id: string
  scan_type: ScanType
  timestamp: string
  risk_level: RiskLevel
  predicted_class: 'spam' | 'legitimate' | null
  model_confidence: number | null
  warning_signs: string[]
  risk_indicators: string[]
}

type ScanHistoryRecord = ScanHistoryItem & {
  recommendations: string[]
  explanation: string
  details: Record<string, unknown>
}

type ScanHistoryResponse = {
  total: number
  limit: number
  offset: number
  scan_type: ScanType | null
  items: ScanHistoryItem[]
}

type DashboardSummary = {
  total_scans: number
  scan_type_counts: Record<ScanType, number>
  risk_level_counts: Record<RiskLevel, number>
  latest_scan_at: string | null
  recent_scans: ScanHistoryItem[]
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string')
}

function isScanType(value: unknown): value is ScanType {
  return value === 'message' || value === 'url' || value === 'screenshot'
}

function isRiskLevel(value: unknown): value is RiskLevel {
  return (
    value === 'elevated' ||
    value === 'unconfirmed' ||
    value === 'caution' ||
    value === 'unverified'
  )
}

function isScanHistoryItem(value: unknown): value is ScanHistoryItem {
  if (!isRecord(value)) {
    return false
  }
  return (
    typeof value.scan_id === 'string' &&
    isScanType(value.scan_type) &&
    typeof value.timestamp === 'string' &&
    isRiskLevel(value.risk_level) &&
    (value.predicted_class === null ||
      value.predicted_class === 'spam' ||
      value.predicted_class === 'legitimate') &&
    (value.model_confidence === null ||
      (typeof value.model_confidence === 'number' &&
        Number.isFinite(value.model_confidence) &&
        value.model_confidence >= 0 &&
        value.model_confidence <= 1)) &&
    isStringArray(value.warning_signs) &&
    isStringArray(value.risk_indicators)
  )
}

function isScanHistoryResponse(value: unknown): value is ScanHistoryResponse {
  if (!isRecord(value)) {
    return false
  }
  return (
    typeof value.total === 'number' &&
    Number.isInteger(value.total) &&
    value.total >= 0 &&
    typeof value.limit === 'number' &&
    typeof value.offset === 'number' &&
    (value.scan_type === null || isScanType(value.scan_type)) &&
    Array.isArray(value.items) &&
    value.items.every(isScanHistoryItem)
  )
}

function isScanHistoryRecord(value: unknown): value is ScanHistoryRecord {
  if (!isRecord(value) || !isScanHistoryItem(value)) {
    return false
  }
  const record = value as Record<string, unknown>
  return (
    isStringArray(record.recommendations) &&
    typeof record.explanation === 'string' &&
    isRecord(record.details)
  )
}

function isDashboardSummary(value: unknown): value is DashboardSummary {
  if (!isRecord(value) || !isRecord(value.scan_type_counts) || !isRecord(value.risk_level_counts)) {
    return false
  }
  const scanTypeCounts = value.scan_type_counts
  const riskLevelCounts = value.risk_level_counts
  return (
    typeof value.total_scans === 'number' &&
    Number.isInteger(value.total_scans) &&
    value.total_scans >= 0 &&
    ['message', 'url', 'screenshot'].every(
      (type) => typeof scanTypeCounts[type] === 'number',
    ) &&
    ['elevated', 'unconfirmed', 'caution', 'unverified'].every(
      (level) => typeof riskLevelCounts[level] === 'number',
    ) &&
    (value.latest_scan_at === null || typeof value.latest_scan_at === 'string') &&
    Array.isArray(value.recent_scans) &&
    value.recent_scans.every(isScanHistoryItem)
  )
}

function isAnalyzeMessageResponse(value: unknown): value is AnalyzeMessageResponse {
  if (typeof value !== 'object' || value === null) {
    return false
  }

  const response = value as Record<string, unknown>
  return (
    (response.predicted_label === 'spam' || response.predicted_label === 'legitimate') &&
    (response.risk_level === 'elevated' || response.risk_level === 'unconfirmed') &&
    typeof response.model_probability === 'number' &&
    Number.isFinite(response.model_probability) &&
    response.model_probability >= 0 &&
    response.model_probability <= 1 &&
    typeof response.explanation === 'string' &&
    Array.isArray(response.warning_signs) &&
    response.warning_signs.every((item) => typeof item === 'string') &&
    Array.isArray(response.recommendations) &&
    response.recommendations.every((item) => typeof item === 'string')
  )
}

type ExtractTextResponse = {
  success: boolean
  extracted_text: string
  message: string
}

function isExtractTextResponse(value: unknown): value is ExtractTextResponse {
  if (typeof value !== 'object' || value === null) {
    return false
  }

  const response = value as Record<string, unknown>
  return (
    typeof response.success === 'boolean' &&
    typeof response.extracted_text === 'string' &&
    typeof response.message === 'string'
  )
}

function isAnalyzeURLResponse(value: unknown): value is AnalyzeURLResponse {
  if (typeof value !== 'object' || value === null) {
    return false
  }

  const response = value as Record<string, unknown>
  return (
    (response.risk_level === 'unverified' || response.risk_level === 'caution') &&
    Array.isArray(response.risk_indicators) &&
    response.risk_indicators.every((item) => typeof item === 'string') &&
    typeof response.explanation === 'string' &&
    Array.isArray(response.warning_signs) &&
    response.warning_signs.every((item) => typeof item === 'string') &&
    Array.isArray(response.recommendations) &&
    response.recommendations.every((item) => typeof item === 'string')
  )
}

function formatRiskIndicator(indicator: string): string {
  const knownLabels: Record<string, string> = {
    ip_address_host: 'IP address used as host',
    excessive_subdomains: 'Several nested subdomains',
    at_symbol_in_authority: '@ symbol in URL authority',
    url_shortener: 'URL shortener',
    internationalized_domain: 'Encoded internationalized domain',
    many_hyphens: 'Several hyphens in hostname',
    account_related_hostname: 'Account-related hostname wording',
  }

  return knownLabels[indicator] ?? indicator.replaceAll('_', ' ')
}

function formatScanType(scanType: ScanType): string {
  if (scanType === 'url') {
    return 'URL'
  }
  return scanType === 'screenshot' ? 'Screenshot' : 'Message'
}

function formatTimestamp(timestamp: string): string {
  const parsedDate = new Date(timestamp)
  if (Number.isNaN(parsedDate.getTime())) {
    return 'Date unavailable'
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(parsedDate)
}

function riskBadgeClass(riskLevel: RiskLevel): string {
  if (riskLevel === 'caution' || riskLevel === 'unverified') {
    return `risk-badge risk-url-${riskLevel}`
  }
  return `risk-badge risk-${riskLevel}`
}

async function requestMessageAnalysis(message: string): Promise<AnalyzeMessageResponse> {
  return requestMessageAnalysisAt('/api/analyze-message', { message })
}

async function requestScreenshotAnalysis(extractedText: string): Promise<AnalyzeMessageResponse> {
  return requestMessageAnalysisAt('/api/analyze-screenshot', {
    extracted_text: extractedText,
  })
}

async function requestMessageAnalysisAt(
  path: string,
  payload: { message: string } | { extracted_text: string },
): Promise<AnalyzeMessageResponse> {
  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
  } catch {
    throw new Error('Could not reach the ScamShield AI backend. Check that the API is running and try again.')
  }

  let responseBody: unknown
  try {
    responseBody = await response.json()
  } catch {
    throw new Error('The backend returned an unreadable response. Please try again.')
  }

  if (!response.ok) {
    if (response.status === 422) {
      throw new Error('The backend could not validate this message. Check the input and try again.')
    }
    if (response.status === 503) {
      throw new Error('The SMS classifier is not ready yet. Please try again later.')
    }
    if (response.status >= 500) {
      throw new Error('The backend could not complete the scan. Please try again later.')
    }
    throw new Error('The backend could not process this request. Please try again.')
  }

  if (!isAnalyzeMessageResponse(responseBody)) {
    throw new Error('The backend response was incomplete or unexpected. No result was displayed.')
  }

  return responseBody
}

async function requestJson(path: string, fallbackMessage: string, init?: RequestInit): Promise<unknown> {
  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}${path}`, init)
  } catch {
    throw new Error('Could not reach the ScamShield AI backend. Check that the API is running and try again.')
  }

  let responseBody: unknown
  try {
    responseBody = await response.json()
  } catch {
    throw new Error('The backend returned an unreadable response. Please try again.')
  }

  if (!response.ok) {
    if (isRecord(responseBody) && typeof responseBody.detail === 'string') {
      throw new Error(responseBody.detail)
    }
    throw new Error(fallbackMessage)
  }
  return responseBody
}

async function requestScanHistory(offset: number): Promise<ScanHistoryResponse> {
  const params = new URLSearchParams({
    limit: String(SCAN_HISTORY_PAGE_SIZE),
    offset: String(offset),
  })
  const response = await requestJson(
    `/api/scan-history?${params.toString()}`,
    'Could not load scan history. Please try again.',
  )
  if (!isScanHistoryResponse(response)) {
    throw new Error('The backend returned an incomplete scan history response.')
  }
  return response
}

async function requestDashboardSummary(): Promise<DashboardSummary> {
  const response = await requestJson(
    '/api/dashboard/summary',
    'Could not load dashboard statistics. Please try again.',
  )
  if (!isDashboardSummary(response)) {
    throw new Error('The backend returned incomplete dashboard statistics.')
  }
  return response
}

async function requestScanDetails(scanId: string): Promise<ScanHistoryRecord> {
  const response = await requestJson(
    `/api/scan-history/${encodeURIComponent(scanId)}`,
    'Could not load this scan. Please try again.',
  )
  if (!isScanHistoryRecord(response)) {
    throw new Error('The backend returned incomplete scan details.')
  }
  return response
}

async function requestClearScanHistory(): Promise<number> {
  const response = await requestJson(
    '/api/scan-history',
    'Could not clear scan history. Please try again.',
    { method: 'DELETE' },
  )
  if (!isRecord(response) || typeof response.deleted_count !== 'number') {
    throw new Error('The backend returned an unexpected clear-history response.')
  }
  return response.deleted_count
}

function ShieldIcon({ className = '' }: { className?: string }) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      fill="none"
      viewBox="0 0 24 24"
    >
      <path
        d="M12 3 19 6v5.3c0 4.5-2.9 7.7-7 9.7-4.1-2-7-5.2-7-9.7V6l7-3Z"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.7"
      />
      <path
        d="m9 12 2 2 4-4"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.7"
      />
    </svg>
  )
}

function ArrowIcon({ className = '' }: { className?: string }) {
  return (
    <svg
      aria-hidden="true"
      className={className}
      fill="none"
      viewBox="0 0 20 20"
    >
      <path
        d="M4.5 10h11m-4.5-4.5L15.5 10 11 14.5"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.6"
      />
    </svg>
  )
}

function ScanIcon() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24">
      <path
        d="M8 3H5a2 2 0 0 0-2 2v3m13-5h3a2 2 0 0 1 2 2v3M3 16v3a2 2 0 0 0 2 2h3m13-5v3a2 2 0 0 1-2 2h-3M7 12h10m-5-5v10"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.7"
      />
    </svg>
  )
}

function LinkIcon() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24">
      <path
        d="m10 13.5 4-4m-6.1 6.6-1.4 1.4a4 4 0 0 1-5.7-5.7l4-4a4 4 0 0 1 5.7 0m3.4 2.2 1.4-1.4a4 4 0 0 1 5.7 5.7l-4 4a4 4 0 0 1-5.7 0"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.7"
      />
    </svg>
  )
}

function ImageIcon() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24">
      <rect
        height="16"
        rx="2.5"
        stroke="currentColor"
        strokeWidth="1.7"
        width="18"
        x="3"
        y="4"
      />
      <circle cx="8.5" cy="9" r="1.5" stroke="currentColor" strokeWidth="1.7" />
      <path
        d="m21 15-5-5L5 20"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.7"
      />
    </svg>
  )
}

function MessageIcon() {
  return (
    <svg aria-hidden="true" fill="none" viewBox="0 0 24 24">
      <path
        d="M20 11.5a7.5 7.5 0 0 1-8 7.5 8.6 8.6 0 0 1-3.5-.8L4 20l1.2-3.7A7.2 7.2 0 0 1 4 12.5 7.5 7.5 0 0 1 12 5a7.5 7.5 0 0 1 8 6.5Z"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.7"
      />
      <path
        d="M8 12h8m-8 3h5"
        stroke="currentColor"
        strokeLinecap="round"
        strokeWidth="1.7"
      />
    </svg>
  )
}

function MessageAnalysisResult({
  result,
  titleId,
  eyebrow,
}: {
  result: AnalyzeMessageResponse
  titleId: string
  eyebrow: string
}) {
  return (
    <section
      aria-labelledby={titleId}
      aria-live="polite"
      className="scan-result"
    >
      <div className="scan-result-header">
        <div>
          <span className="result-eyebrow">{eyebrow}</span>
          <h3 id={titleId}>Scan result</h3>
        </div>
        <span className={`risk-badge risk-${result.risk_level}`}>
          {result.risk_level === 'elevated' ? 'Elevated risk' : 'Unconfirmed'}
        </span>
      </div>
      <div className="result-summary">
        <span className="result-label">
          Predicted class: <strong>{result.predicted_label}</strong>
        </span>
        <span className="result-confidence">
          Model confidence: <strong>{(result.model_probability * 100).toFixed(1)}%</strong>
        </span>
      </div>
      <p className="result-confidence-note">
        Model confidence is not a guaranteed probability that this message is a scam.
      </p>
      <p className="result-explanation">{result.explanation}</p>
      <div className="result-details">
        <div>
          <h4>Warning signs</h4>
          {result.warning_signs.length > 0 ? (
            <ul>
              {result.warning_signs.map((sign, index) => (
                <li key={`${sign}-${index}`}>{sign}</li>
              ))}
            </ul>
          ) : (
            <p className="result-empty">
              No common warning signs were identified. This does not confirm the message is safe.
            </p>
          )}
        </div>
        <div>
          <h4>Recommendations</h4>
          {result.recommendations.length > 0 ? (
            <ul>
              {result.recommendations.map((recommendation, index) => (
                <li key={`${recommendation}-${index}`}>{recommendation}</li>
              ))}
            </ul>
          ) : (
            <p className="result-empty">No recommendations were returned.</p>
          )}
        </div>
      </div>
    </section>
  )
}

function App() {
  const [message, setMessage] = useState('')
  const [result, setResult] = useState<AnalyzeMessageResponse | null>(null)
  const [error, setError] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [url, setUrl] = useState('')
  const [urlResult, setUrlResult] = useState<AnalyzeURLResponse | null>(null)
  const [urlError, setUrlError] = useState('')
  const [isURLLoading, setIsURLLoading] = useState(false)
  const [screenshotFile, setScreenshotFile] = useState<File | null>(null)
  const [screenshotPreview, setScreenshotPreview] = useState('')
  const [extractedText, setExtractedText] = useState('')
  const [screenshotResult, setScreenshotResult] = useState<AnalyzeMessageResponse | null>(null)
  const [screenshotError, setScreenshotError] = useState('')
  const [screenshotStatus, setScreenshotStatus] = useState('')
  const [isExtracting, setIsExtracting] = useState(false)
  const [isAnalyzingScreenshot, setIsAnalyzingScreenshot] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)
  const [history, setHistory] = useState<ScanHistoryResponse | null>(null)
  const [historyOffset, setHistoryOffset] = useState(0)
  const [historyLoading, setHistoryLoading] = useState(true)
  const [historyError, setHistoryError] = useState('')
  const [dashboardSummary, setDashboardSummary] = useState<DashboardSummary | null>(null)
  const [dashboardLoading, setDashboardLoading] = useState(true)
  const [dashboardError, setDashboardError] = useState('')
  const [isClearingHistory, setIsClearingHistory] = useState(false)
  const [clearHistoryError, setClearHistoryError] = useState('')
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null)
  const [selectedScan, setSelectedScan] = useState<ScanHistoryRecord | null>(null)
  const [isLoadingScanDetails, setIsLoadingScanDetails] = useState(false)
  const [scanDetailsError, setScanDetailsError] = useState('')

  async function loadHistoryPage(offset: number) {
    setHistoryLoading(true)
    setHistoryError('')
    setHistoryOffset(offset)
    try {
      setHistory(await requestScanHistory(offset))
    } catch (requestError) {
      setHistory(null)
      setHistoryError(
        requestError instanceof Error
          ? requestError.message
          : 'Could not load scan history. Please try again.',
      )
    } finally {
      setHistoryLoading(false)
    }
  }

  async function loadDashboard() {
    setDashboardLoading(true)
    setDashboardError('')
    try {
      setDashboardSummary(await requestDashboardSummary())
    } catch (requestError) {
      setDashboardSummary(null)
      setDashboardError(
        requestError instanceof Error
          ? requestError.message
          : 'Could not load dashboard statistics. Please try again.',
      )
    } finally {
      setDashboardLoading(false)
    }
  }

  useEffect(() => {
    let active = true
    void requestScanHistory(0)
      .then((response) => {
        if (active) {
          setHistory(response)
          setHistoryOffset(0)
        }
      })
      .catch((requestError: unknown) => {
        if (active) {
          setHistory(null)
          setHistoryError(
            requestError instanceof Error
              ? requestError.message
              : 'Could not load scan history. Please try again.',
          )
        }
      })
      .finally(() => {
        if (active) {
          setHistoryLoading(false)
        }
      })

    void requestDashboardSummary()
      .then((response) => {
        if (active) {
          setDashboardSummary(response)
        }
      })
      .catch((requestError: unknown) => {
        if (active) {
          setDashboardSummary(null)
          setDashboardError(
            requestError instanceof Error
              ? requestError.message
              : 'Could not load dashboard statistics. Please try again.',
          )
        }
      })
      .finally(() => {
        if (active) {
          setDashboardLoading(false)
        }
      })

    return () => {
      active = false
    }
  }, [])

  useEffect(() => {
    return () => {
      if (screenshotPreview) {
        URL.revokeObjectURL(screenshotPreview)
      }
    }
  }, [screenshotPreview])

  async function refreshHistoryAfterScan() {
    await Promise.all([loadHistoryPage(0), loadDashboard()])
  }

  async function handleOpenScanDetails(scanId: string) {
    setSelectedScanId(scanId)
    setSelectedScan(null)
    setScanDetailsError('')
    setIsLoadingScanDetails(true)
    try {
      setSelectedScan(await requestScanDetails(scanId))
    } catch (requestError) {
      setScanDetailsError(
        requestError instanceof Error
          ? requestError.message
          : 'Could not load this scan. Please try again.',
      )
    } finally {
      setIsLoadingScanDetails(false)
    }
  }

  function closeScanDetails() {
    setSelectedScanId(null)
    setSelectedScan(null)
    setScanDetailsError('')
  }

  async function handleClearHistory() {
    if (!window.confirm('Clear all saved scan history? This cannot be undone.')) {
      return
    }

    setIsClearingHistory(true)
    setClearHistoryError('')
    try {
      await requestClearScanHistory()
      closeScanDetails()
      await Promise.all([loadHistoryPage(0), loadDashboard()])
    } catch (requestError) {
      setClearHistoryError(
        requestError instanceof Error
          ? requestError.message
          : 'Could not clear scan history. Please try again.',
      )
    } finally {
      setIsClearingHistory(false)
    }
  }

  async function handleAnalyze() {
    const submittedMessage = message.trim()
    if (!submittedMessage) {
      setResult(null)
      setError('Enter a message before starting a scan.')
      return
    }

    setResult(null)
    setError('')
    setIsLoading(true)

    try {
      setResult(await requestMessageAnalysis(submittedMessage))
      await refreshHistoryAfterScan()
    } catch (requestError) {
      setError(
        requestError instanceof Error
          ? requestError.message
          : 'An unexpected error occurred. Please try again.',
      )
    } finally {
      setIsLoading(false)
    }
  }

  function handleClear() {
    setMessage('')
    setResult(null)
    setError('')
  }

  function handleScreenshotFileChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.currentTarget.files?.[0]
    event.currentTarget.value = ''
    if (!file) {
      return
    }

    const extension = file.name.split('.').pop()?.toLowerCase() ?? ''
    const expectedMimeType = IMAGE_MIME_TYPES[extension]
    let validationError = ''
    if (file.size === 0) {
      validationError = 'This image file is empty. Choose a non-empty PNG, JPG, JPEG, or WEBP image.'
    } else if (file.size > MAX_IMAGE_SIZE_BYTES) {
      validationError = 'This image is larger than the 5 MB limit. Choose a smaller image.'
    } else if (!expectedMimeType || (file.type && file.type.toLowerCase() !== expectedMimeType)) {
      validationError = 'Unsupported image format. Choose a PNG, JPG, JPEG, or WEBP image.'
    }

    setScreenshotFile(null)
    setScreenshotPreview('')
    setExtractedText('')
    setScreenshotResult(null)
    setScreenshotStatus('')
    setScreenshotError(validationError)
    if (validationError) {
      return
    }

    setScreenshotFile(file)
    setScreenshotPreview(URL.createObjectURL(file))
  }

  async function handleExtractText() {
    if (!screenshotFile) {
      setScreenshotError('Choose a PNG, JPG, JPEG, or WEBP image before extracting text.')
      return
    }

    setScreenshotError('')
    setScreenshotStatus('')
    setScreenshotResult(null)
    setIsExtracting(true)

    try {
      const formData = new FormData()
      formData.append('file', screenshotFile)

      let response: Response
      try {
        response = await fetch(`${API_BASE_URL}/api/extract-text`, {
          method: 'POST',
          body: formData,
        })
      } catch {
        throw new Error('Could not reach the ScamShield AI backend. Check that the API is running and try again.')
      }

      let responseBody: unknown
      try {
        responseBody = await response.json()
      } catch {
        throw new Error('The backend returned an unreadable response. Please try again.')
      }

      if (!response.ok) {
        if (response.status === 400) {
          throw new Error('The image could not be read. Choose a clear PNG, JPG, JPEG, or WEBP screenshot and try again.')
        }
        if (response.status === 413) {
          throw new Error('The image is larger than the 5 MB limit. Choose a smaller image.')
        }
        if (response.status === 415) {
          throw new Error('Unsupported image format. Choose a PNG, JPG, JPEG, or WEBP image.')
        }
        if (response.status === 422) {
          throw new Error('No readable text was found, or the image could not be processed. Try a clearer screenshot.')
        }
        if (response.status === 503) {
          throw new Error('The OCR service is unavailable because Tesseract is not ready on the backend. Please try again later.')
        }
        if (response.status >= 500) {
          throw new Error('The backend could not complete text extraction. Please try again later.')
        }
        throw new Error('The backend could not process this image. Please try again.')
      }

      if (!isExtractTextResponse(responseBody)) {
        throw new Error('The backend response was incomplete or unexpected. No text was displayed.')
      }
      if (!responseBody.success) {
        throw new Error(responseBody.message || 'The backend could not extract text from this image.')
      }
      if (!responseBody.extracted_text.trim()) {
        throw new Error('No readable text was returned. Try a clearer screenshot.')
      }

      setExtractedText(responseBody.extracted_text)
      setScreenshotStatus(responseBody.message || 'Text extracted successfully. Review or edit it below.')
    } catch (requestError) {
      setScreenshotError(
        requestError instanceof Error
          ? requestError.message
          : 'An unexpected error occurred during text extraction. Please try again.',
      )
    } finally {
      setIsExtracting(false)
    }
  }

  async function handleAnalyzeExtractedText() {
    const submittedMessage = extractedText.trim()
    if (!submittedMessage) {
      setScreenshotResult(null)
      setScreenshotError('Enter or extract message text before starting an analysis.')
      return
    }

    setScreenshotResult(null)
    setScreenshotError('')
    setScreenshotStatus('')
    setIsAnalyzingScreenshot(true)

    try {
      setScreenshotResult(await requestScreenshotAnalysis(submittedMessage))
      await refreshHistoryAfterScan()
    } catch (requestError) {
      setScreenshotError(
        requestError instanceof Error
          ? requestError.message
          : 'An unexpected error occurred during message analysis. Please try again.',
      )
    } finally {
      setIsAnalyzingScreenshot(false)
    }
  }

  async function handleAnalyzeURL(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const submittedURL = url.trim()
    if (!submittedURL) {
      setUrlResult(null)
      setUrlError('Enter a URL before starting a scan.')
      return
    }

    setUrlResult(null)
    setUrlError('')
    setIsURLLoading(true)

    try {
      let response: Response
      try {
        response = await fetch(`${API_BASE_URL}/api/analyze-url`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: submittedURL }),
        })
      } catch {
        throw new Error('Could not reach the ScamShield AI backend. Check that the API is running and try again.')
      }

      let responseBody: unknown
      try {
        responseBody = await response.json()
      } catch {
        throw new Error('The backend returned an unreadable response. Please try again.')
      }

      if (!response.ok) {
        if (response.status === 422) {
          throw new Error('The URL could not be validated. Enter a valid HTTP or HTTPS URL and try again.')
        }
        if (response.status >= 500) {
          throw new Error('The backend could not complete the URL scan. Please try again later.')
        }
        throw new Error('The backend could not process this URL. Please try again.')
      }

      if (!isAnalyzeURLResponse(responseBody)) {
        throw new Error('The backend response was incomplete or unexpected. No result was displayed.')
      }

      setUrlResult(responseBody)
      await refreshHistoryAfterScan()
    } catch (requestError) {
      setUrlError(
        requestError instanceof Error
          ? requestError.message
          : 'An unexpected error occurred. Please try again.',
      )
    } finally {
      setIsURLLoading(false)
    }
  }

  function closeMenu() {
    setMenuOpen(false)
  }

  return (
    <>
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <header className="site-header">
        <div className="header-inner">
          <a aria-label="ScamShield AI home" className="brand" href="#home">
            <span className="brand-mark">
              <ShieldIcon />
            </span>
            <span className="brand-name">
              ScamShield <span>AI</span>
            </span>
          </a>

          <button
            aria-expanded={menuOpen}
            aria-label={menuOpen ? 'Close navigation menu' : 'Open navigation menu'}
            className="menu-toggle"
            onClick={() => setMenuOpen(!menuOpen)}
            type="button"
          >
            <span />
            <span />
          </button>

          <nav
            aria-label="Main navigation"
            className={`main-nav${menuOpen ? ' is-open' : ''}`}
          >
            <a href="#home" onClick={closeMenu}>Home</a>
            <a href="#message-scanner" onClick={closeMenu}>Message Scanner</a>
            <a href="#screenshot-scanner" onClick={closeMenu}>Screenshot Scanner</a>
            <a href="#url-scanner" onClick={closeMenu}>URL Scanner</a>
            <a href="#scan-history" onClick={closeMenu}>Scan History</a>
            <a href="#how-it-works" onClick={closeMenu}>How It Works</a>
            <a href="#about" onClick={closeMenu}>About</a>
          </nav>

          <a className="button button-small button-outline header-cta" href="#message-scanner">
            Get Started <ArrowIcon />
          </a>
        </div>
      </header>

      <main id="main-content">
        <section aria-labelledby="hero-title" className="hero-section" id="home">
          <div className="hero-inner page-container">
            <div className="hero-copy">
              <div className="eyebrow hero-eyebrow">
                <span className="eyebrow-dot" />
                AI-Powered Digital Protection
              </div>
              <h1 id="hero-title">
                Stay one step
                <br />
                ahead of <span>scams.</span>
              </h1>
              <p className="hero-description">
                Suspicious message? Unfamiliar link? ScamShield AI helps you
                pause, spot the warning signs, and make a more informed choice.
              </p>
              <div className="hero-actions">
                <a className="button button-primary" href="#message-scanner">
                  Scan a Message <ArrowIcon />
                </a>
                <a className="button button-text" href="#how-it-works">
                  Explore Protection <ArrowIcon />
                </a>
              </div>
              <div className="hero-note">
                <ShieldIcon />
                <span>Built to help you stay informed, not alarmed.</span>
              </div>
            </div>

            <div aria-label="ScamShield protection dashboard illustration" className="hero-visual" role="img">
              <div className="visual-orbit orbit-outer" />
              <div className="visual-orbit orbit-inner" />
              <div className="visual-glow" />
              <div className="dashboard-card">
                <div className="dashboard-top">
                  <div className="dashboard-brand">
                    <span className="mini-shield"><ShieldIcon /></span>
                    <span>ScamShield <b>AI</b></span>
                  </div>
                  <span className="dashboard-live"><span /> Protection ready</span>
                </div>
                <div className="dashboard-content">
                  <div className="dashboard-heading">
                    <div>
                      <span className="dashboard-label">YOUR DIGITAL SAFETY</span>
                      <h2>Look closer.<br />Feel more confident.</h2>
                    </div>
                    <div className="shield-illustration">
                      <ShieldIcon />
                      <span className="shield-check">✓</span>
                    </div>
                  </div>
                  <div className="signal-card">
                    <div className="signal-icon"><MessageIcon /></div>
                    <div className="signal-copy">
                      <strong>Suspicious message?</strong>
                      <span>Take a moment before you act.</span>
                    </div>
                    <span className="signal-arrow"><ArrowIcon /></span>
                  </div>
                  <div className="signal-card">
                    <div className="signal-icon signal-icon-link"><LinkIcon /></div>
                    <div className="signal-copy">
                      <strong>Unexpected link?</strong>
                      <span>Check it before you click.</span>
                    </div>
                    <span className="signal-arrow"><ArrowIcon /></span>
                  </div>
                </div>
                <div className="dashboard-footer">
                  <span className="footer-lock"><ShieldIcon /></span>
                  <span>Your safety starts with a second look.</span>
                  <span className="footer-dots">•••</span>
                </div>
              </div>
              <div className="floating-chip">
                <span className="chip-check">✓</span>
                <span><b>Pause.</b> Check. Protect.</span>
              </div>
              <div className="visual-caption">A little awareness goes a long way.</div>
            </div>
          </div>
          <div aria-hidden="true" className="hero-bottom-line" />
        </section>

        <section aria-labelledby="scanner-title" className="scanner-section section-padding" id="message-scanner">
          <div className="page-container">
            <div className="section-heading scanner-heading">
              <div>
                <div className="eyebrow"><span className="eyebrow-dash" /> MESSAGE SCANNER</div>
                <h2 id="scanner-title">Check before you trust.</h2>
                <p>Got a message that doesn’t feel right? Bring it here before you respond.</p>
              </div>
              <div aria-hidden="true" className="scanner-decoration"><ScanIcon /></div>
            </div>

            <div className="scanner-panel">
              <div className="scanner-panel-top">
                <div className="scanner-panel-title">
                  <span className="panel-icon"><MessageIcon /></span>
                  <div>
                    <h3>Message check</h3>
                    <p>Paste the text you want to review</p>
                  </div>
                </div>
                <span className="privacy-label"><ShieldIcon /> Sent to the configured backend</span>
              </div>
              <label className="visually-hidden" htmlFor="message-input">
                Suspicious message to check
              </label>
              <textarea
                id="message-input"
                disabled={isLoading}
                maxLength={MAX_MESSAGE_LENGTH}
                onChange={(event) => {
                  setMessage(event.target.value)
                  setResult(null)
                  setError('')
                }}
                placeholder="Paste a suspicious text, email, or direct message here..."
                value={message}
              />
              <div className="scanner-controls">
                <span aria-live="polite" className="character-count">
                  {message.length} / {MAX_MESSAGE_LENGTH} characters
                </span>
                <div className="scanner-buttons">
                  <button
                    className="button button-clear"
                    disabled={isLoading}
                    onClick={handleClear}
                    type="button"
                  >
                    Clear
                  </button>
                  <button
                    aria-busy={isLoading}
                    className="button button-primary analyze-button"
                    disabled={isLoading}
                    onClick={handleAnalyze}
                    type="button"
                  >
                    {isLoading ? (
                      <>
                        <span aria-hidden="true" className="loading-spinner" />
                        Analyzing message...
                      </>
                    ) : (
                      <>
                        <ScanIcon /> Scan Message <ArrowIcon />
                      </>
                    )}
                  </button>
                </div>
              </div>
              {isLoading && <p className="scanner-status" role="status">Analyzing message...</p>}
              {error && <p className="scanner-error" role="alert">{error}</p>}
              {result && (
                <MessageAnalysisResult
                  eyebrow="SMS SPAM CLASSIFIER"
                  result={result}
                  titleId="scan-result-title"
                />
              )}
              <p className="scanner-disclaimer">
                Messages are sent to the ScamShield AI backend for SMS spam classification. Never submit passwords, payment details, or other sensitive information.
              </p>
            </div>
          </div>
        </section>

        <section
          aria-labelledby="screenshot-scanner-title"
          className="scanner-section screenshot-scanner-section section-padding"
          id="screenshot-scanner"
        >
          <div className="page-container">
            <div className="section-heading scanner-heading">
              <div>
                <div className="eyebrow"><span className="eyebrow-dash" /> SCREENSHOT SCANNER</div>
                <h2 id="screenshot-scanner-title">Read the message, not the link.</h2>
                <p>Extract text from a screenshot, review it, then analyze the message without opening any links.</p>
              </div>
              <div aria-hidden="true" className="scanner-decoration"><ImageIcon /></div>
            </div>

            <div className="scanner-panel screenshot-panel">
              <div className="scanner-panel-top">
                <div className="scanner-panel-title">
                  <span className="panel-icon"><ImageIcon /></span>
                  <div>
                    <h3>Screenshot OCR</h3>
                    <p>Choose an image to extract message text</p>
                  </div>
                </div>
                <span className="privacy-label"><ShieldIcon /> Sent to the configured backend</span>
              </div>

              <label className="screenshot-upload-label" htmlFor="screenshot-input">
                Screenshot image
              </label>
              <input
                accept=".png,.jpg,.jpeg,.webp,image/png,image/jpeg,image/webp"
                className="screenshot-file-input"
                disabled={isExtracting || isAnalyzingScreenshot}
                id="screenshot-input"
                onChange={handleScreenshotFileChange}
                type="file"
              />
              <p className="screenshot-file-note">PNG, JPG, JPEG, or WEBP. Maximum file size: 5 MB.</p>

              {screenshotPreview && (
                <div className="screenshot-preview">
                  <img alt="Preview of selected screenshot" src={screenshotPreview} />
                  <span>{screenshotFile?.name}</span>
                </div>
              )}

              <div className="scanner-controls screenshot-controls">
                <span className="character-count">
                  Links found in the screenshot are never opened or visited.
                </span>
                <div className="scanner-buttons">
                  <button
                    aria-busy={isExtracting}
                    className="button button-primary analyze-button"
                    disabled={isExtracting || isAnalyzingScreenshot}
                    onClick={handleExtractText}
                    type="button"
                  >
                    {isExtracting ? (
                      <>
                        <span aria-hidden="true" className="loading-spinner" />
                        Extracting text...
                      </>
                    ) : (
                      <>
                        <ImageIcon /> Extract Text <ArrowIcon />
                      </>
                    )}
                  </button>
                </div>
              </div>

              {isExtracting && <p className="scanner-status" role="status">Extracting text from the selected image...</p>}
              {screenshotStatus && <p className="scanner-status" role="status">{screenshotStatus}</p>}
              {screenshotError && <p className="scanner-error" role="alert">{screenshotError}</p>}

              <label className="screenshot-upload-label extracted-text-label" htmlFor="extracted-text">
                Extracted text (editable)
              </label>
              <textarea
                disabled={isExtracting || isAnalyzingScreenshot}
                id="extracted-text"
                maxLength={MAX_EXTRACTED_MESSAGE_LENGTH}
                onChange={(event) => {
                  setExtractedText(event.target.value)
                  setScreenshotResult(null)
                  setScreenshotError('')
                }}
                placeholder="Extracted message text will appear here. You can also enter or edit it before analysis."
                value={extractedText}
              />
              <div className="scanner-controls">
                <span aria-live="polite" className="character-count">
                  {extractedText.length} / {MAX_EXTRACTED_MESSAGE_LENGTH} characters
                </span>
                <div className="scanner-buttons">
                  <button
                    aria-busy={isAnalyzingScreenshot}
                    className="button button-primary analyze-button"
                    disabled={isExtracting || isAnalyzingScreenshot}
                    onClick={handleAnalyzeExtractedText}
                    type="button"
                  >
                    {isAnalyzingScreenshot ? (
                      <>
                        <span aria-hidden="true" className="loading-spinner" />
                        Analyzing text...
                      </>
                    ) : (
                      <>
                        <ScanIcon /> Analyze Extracted Text <ArrowIcon />
                      </>
                    )}
                  </button>
                </div>
              </div>

              {isAnalyzingScreenshot && <p className="scanner-status" role="status">Analyzing the edited message text...</p>}
              {screenshotResult && (
                <MessageAnalysisResult
                  eyebrow="SCREENSHOT MESSAGE ANALYSIS"
                  result={screenshotResult}
                  titleId="screenshot-result-title"
                />
              )}
              <p className="scanner-disclaimer">
                Text is sent to the configured backend for OCR and message analysis. Review the extracted text before analysis, and never submit sensitive information.
              </p>
            </div>
          </div>
        </section>

        <section aria-labelledby="url-scanner-title" className="scanner-section url-scanner-section section-padding" id="url-scanner">
          <div className="page-container">
            <div className="section-heading scanner-heading">
              <div>
                <div className="eyebrow"><span className="eyebrow-dash" /> URL SCANNER</div>
                <h2 id="url-scanner-title">Pause before you open.</h2>
                <p>Review basic URL patterns without visiting the submitted address.</p>
              </div>
              <div aria-hidden="true" className="scanner-decoration"><LinkIcon /></div>
            </div>

            <div className="scanner-panel">
              <div className="scanner-panel-top">
                <div className="scanner-panel-title">
                  <span className="panel-icon"><LinkIcon /></span>
                  <div>
                    <h3>URL check</h3>
                    <p>Paste the web address you want to review</p>
                  </div>
                </div>
                <span className="privacy-label"><ShieldIcon /> Submitted to the configured backend</span>
              </div>
              <form onSubmit={handleAnalyzeURL}>
                <label className="visually-hidden" htmlFor="url-input">
                  URL to check
                </label>
                <input
                  autoComplete="url"
                  className="url-input"
                  disabled={isURLLoading}
                  id="url-input"
                  maxLength={2048}
                  onChange={(event) => {
                    setUrl(event.target.value)
                    setUrlResult(null)
                    setUrlError('')
                  }}
                  placeholder="https://example.com"
                  spellCheck={false}
                  type="text"
                  value={url}
                />
                <div className="scanner-controls">
                  <span className="character-count">Enter a complete HTTP or HTTPS URL</span>
                  <div className="scanner-buttons">
                    <button
                      aria-busy={isURLLoading}
                      className="button button-primary analyze-button"
                      disabled={isURLLoading}
                      type="submit"
                    >
                      {isURLLoading ? (
                        <>
                          <span aria-hidden="true" className="loading-spinner" />
                          Analyzing URL...
                        </>
                      ) : (
                        <>
                          <ScanIcon /> Scan URL <ArrowIcon />
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </form>
              {isURLLoading && <p className="scanner-status" role="status">Analyzing URL patterns...</p>}
              {urlError && <p className="scanner-error" role="alert">{urlError}</p>}
              {urlResult && (
                <section
                  aria-labelledby="url-result-title"
                  aria-live="polite"
                  className="scan-result"
                >
                  <div className="scan-result-header">
                    <div>
                      <span className="result-eyebrow">PATTERN-BASED URL REVIEW</span>
                      <h3 id="url-result-title">Scan result</h3>
                    </div>
                    <span className={`risk-badge risk-url-${urlResult.risk_level}`}>
                      {urlResult.risk_level === 'caution' ? 'Caution' : 'Unverified'}
                    </span>
                  </div>
                  <p className="url-result-value">{url.trim()}</p>
                  <p className="result-explanation">{urlResult.explanation}</p>
                  <p className="result-confidence-note">
                    Pattern-based analysis does not prove a URL is malicious or safe. Submitted URLs are not opened or visited.
                  </p>
                  <div className="result-details">
                    <div>
                      <h4>Risk indicators</h4>
                      {urlResult.risk_indicators.length > 0 ? (
                        <ul>
                          {urlResult.risk_indicators.map((indicator, index) => (
                            <li key={`${indicator}-${index}`}>{formatRiskIndicator(indicator)}</li>
                          ))}
                        </ul>
                      ) : (
                        <p className="result-empty">
                          No checked suspicious patterns were identified. The URL remains unverified.
                        </p>
                      )}
                    </div>
                    <div>
                      <h4>Warning signs</h4>
                      {urlResult.warning_signs.length > 0 ? (
                        <ul>
                          {urlResult.warning_signs.map((sign, index) => (
                            <li key={`${sign}-${index}`}>{sign}</li>
                          ))}
                        </ul>
                      ) : (
                        <p className="result-empty">No checked warning signs were identified.</p>
                      )}
                    </div>
                    <div className="url-recommendations">
                      <h4>Recommendations</h4>
                      {urlResult.recommendations.length > 0 ? (
                        <ul>
                          {urlResult.recommendations.map((recommendation, index) => (
                            <li key={`${recommendation}-${index}`}>{recommendation}</li>
                          ))}
                        </ul>
                      ) : (
                        <p className="result-empty">No recommendations were returned.</p>
                      )}
                    </div>
                  </div>
                </section>
              )}
              <p className="scanner-disclaimer">
                This basic pattern review is not a complete phishing detector. Do not treat an unverified result as proof that a URL is safe.
              </p>
            </div>
          </div>
        </section>

        <section
          aria-labelledby="scan-history-title"
          className="scan-history-section section-padding"
          id="scan-history"
        >
          <div className="page-container">
            <div className="section-heading scanner-heading">
              <div>
                <div className="eyebrow"><span className="eyebrow-dash" /> YOUR SCAN ACTIVITY</div>
                <h2 id="scan-history-title">Scan history &amp; dashboard.</h2>
                <p>Review saved scan results and activity from this ScamShield backend.</p>
              </div>
              <div aria-hidden="true" className="scanner-decoration"><ScanIcon /></div>
            </div>

            <section aria-labelledby="dashboard-summary-title" className="history-panel">
              <div className="history-panel-heading">
                <div>
                  <span className="result-eyebrow">OVERVIEW</span>
                  <h3 id="dashboard-summary-title">Dashboard summary</h3>
                </div>
                <button
                  className="button button-outline button-small"
                  disabled={dashboardLoading}
                  onClick={() => void loadDashboard()}
                  type="button"
                >
                  {dashboardLoading ? 'Refreshing...' : 'Refresh'}
                </button>
              </div>

              {dashboardLoading && (
                <p className="history-status" role="status">Loading dashboard statistics...</p>
              )}
              {dashboardError && (
                <div className="history-error" role="alert">
                  <p>{dashboardError}</p>
                  <button
                    className="button button-outline button-small"
                    onClick={() => void loadDashboard()}
                    type="button"
                  >
                    Try again
                  </button>
                </div>
              )}
              {dashboardSummary && (
                <>
                  <div className="dashboard-stat-grid">
                    <article className="dashboard-stat-card dashboard-stat-total">
                      <span>Total scans</span>
                      <strong>{dashboardSummary.total_scans}</strong>
                    </article>
                    {(['message', 'url', 'screenshot'] as const).map((scanType) => (
                      <article className="dashboard-stat-card" key={scanType}>
                        <span>{formatScanType(scanType)} scans</span>
                        <strong>{dashboardSummary.scan_type_counts[scanType]}</strong>
                      </article>
                    ))}
                  </div>
                  <div className="dashboard-risk-summary">
                    <h4>Risk level counts</h4>
                    <div className="dashboard-risk-grid">
                      {(['elevated', 'unconfirmed', 'caution', 'unverified'] as const).map(
                        (riskLevel) => (
                          <div className="dashboard-risk-count" key={riskLevel}>
                            <span className={riskBadgeClass(riskLevel)}>
                              {riskLevel === 'elevated'
                                ? 'Elevated'
                                : riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1)}
                            </span>
                            <strong>{dashboardSummary.risk_level_counts[riskLevel]}</strong>
                          </div>
                        ),
                      )}
                    </div>
                    <p className="dashboard-latest-scan">
                      Latest scan:{' '}
                      {dashboardSummary.latest_scan_at
                        ? formatTimestamp(dashboardSummary.latest_scan_at)
                        : 'No scans yet'}
                    </p>
                  </div>
                </>
              )}
            </section>

            <section aria-labelledby="history-list-title" className="history-panel history-list-panel">
              <div className="history-panel-heading">
                <div>
                  <span className="result-eyebrow">PREVIOUS RESULTS</span>
                  <h3 id="history-list-title">Scan history</h3>
                </div>
                <div className="history-actions">
                  <button
                    className="button button-outline button-small"
                    disabled={historyLoading || isClearingHistory}
                    onClick={() => void loadHistoryPage(historyOffset)}
                    type="button"
                  >
                    {historyLoading ? 'Loading...' : 'Refresh'}
                  </button>
                  <button
                    className="button button-clear button-small"
                    disabled={historyLoading || isClearingHistory || !history || history.total === 0}
                    onClick={() => void handleClearHistory()}
                    type="button"
                  >
                    {isClearingHistory ? 'Clearing...' : 'Clear history'}
                  </button>
                </div>
              </div>

              {historyLoading && (
                <p className="history-status" role="status">Loading scan history...</p>
              )}
              {historyError && (
                <div className="history-error" role="alert">
                  <p>{historyError}</p>
                  <button
                    className="button button-outline button-small"
                    onClick={() => void loadHistoryPage(historyOffset)}
                    type="button"
                  >
                    Try again
                  </button>
                </div>
              )}
              {clearHistoryError && <p className="scanner-error" role="alert">{clearHistoryError}</p>}

              {history && !historyLoading && !historyError && history.total === 0 && (
                <div className="history-empty">
                  <span className="history-empty-icon"><ShieldIcon /></span>
                  <h4>No scans saved yet</h4>
                  <p>Completed message, URL, and screenshot scans will appear here.</p>
                </div>
              )}

              {history && !historyLoading && !historyError && history.total > 0 && (
                <>
                  {history.items.length > 0 ? (
                    <div className="history-list">
                      {history.items.map((item) => (
                        <article className="history-item" key={item.scan_id}>
                          <div className="history-item-main">
                            <div className="history-item-heading">
                              <div>
                                <span className="history-scan-type">{formatScanType(item.scan_type)} scan</span>
                                <time className="history-timestamp" dateTime={item.timestamp}>
                                  {formatTimestamp(item.timestamp)}
                                </time>
                              </div>
                              <span className={riskBadgeClass(item.risk_level)}>
                                {item.risk_level === 'elevated'
                                  ? 'Elevated'
                                  : item.risk_level.charAt(0).toUpperCase() + item.risk_level.slice(1)}
                              </span>
                            </div>
                            <div className="history-item-meta">
                              {item.predicted_class && (
                                <span>
                                  Predicted class: <strong>{item.predicted_class}</strong>
                                </span>
                              )}
                              {item.model_confidence !== null && (
                                <span>
                                  Model confidence: <strong>{(item.model_confidence * 100).toFixed(1)}%</strong>
                                </span>
                              )}
                            </div>
                          </div>
                          <button
                            aria-expanded={selectedScanId === item.scan_id}
                            className="button button-outline button-small history-view-button"
                            disabled={isLoadingScanDetails}
                            onClick={() => {
                              if (selectedScanId === item.scan_id) {
                                closeScanDetails()
                              } else {
                                void handleOpenScanDetails(item.scan_id)
                              }
                            }}
                            type="button"
                          >
                            {isLoadingScanDetails && selectedScanId === item.scan_id
                              ? 'Opening...'
                              : selectedScanId === item.scan_id
                                ? 'Hide details'
                                : 'View details'}
                          </button>
                          {selectedScanId === item.scan_id && (
                            <section
                              aria-busy={isLoadingScanDetails}
                              aria-labelledby={`history-detail-title-${item.scan_id}`}
                              aria-live="polite"
                              className="history-detail history-item-details"
                            >
                              <div className="history-detail-heading">
                                <div>
                                  <span className="result-eyebrow">SAVED RESULT</span>
                                  <h4 id={`history-detail-title-${item.scan_id}`}>
                                    {formatScanType(item.scan_type)} scan details
                                  </h4>
                                </div>
                                <button
                                  className="button button-clear button-small"
                                  onClick={closeScanDetails}
                                  type="button"
                                >
                                  Hide details
                                </button>
                              </div>
                              {isLoadingScanDetails && (
                                <p className="history-status" role="status">Loading scan details...</p>
                              )}
                              {scanDetailsError && (
                                <p className="scanner-error" role="alert">{scanDetailsError}</p>
                              )}
                              {selectedScan?.scan_id === item.scan_id && (
                                <>
                                  <div className="history-detail-summary">
                                    <span>{formatScanType(selectedScan.scan_type)} scan</span>
                                    <time dateTime={selectedScan.timestamp}>
                                      {formatTimestamp(selectedScan.timestamp)}
                                    </time>
                                    <span className={riskBadgeClass(selectedScan.risk_level)}>
                                      {selectedScan.risk_level === 'elevated'
                                        ? 'Elevated'
                                        : selectedScan.risk_level.charAt(0).toUpperCase() +
                                          selectedScan.risk_level.slice(1)}
                                    </span>
                                    {selectedScan.predicted_class && (
                                      <span>
                                        Predicted class: <strong>{selectedScan.predicted_class}</strong>
                                      </span>
                                    )}
                                    {selectedScan.model_confidence !== null && (
                                      <span>
                                        Model confidence:{' '}
                                        <strong>{(selectedScan.model_confidence * 100).toFixed(1)}%</strong>
                                      </span>
                                    )}
                                  </div>
                                  <p className="result-explanation">{selectedScan.explanation}</p>
                                  <div className="result-details history-detail-groups">
                                    <div>
                                      <h4>Warning signs</h4>
                                      {selectedScan.warning_signs.length > 0 ? (
                                        <ul>
                                          {selectedScan.warning_signs.map((sign, index) => (
                                            <li key={`${sign}-${index}`}>{sign}</li>
                                          ))}
                                        </ul>
                                      ) : (
                                        <p className="result-empty">No warning signs were recorded.</p>
                                      )}
                                    </div>
                                    {selectedScan.risk_indicators.length > 0 && (
                                      <div>
                                        <h4>Risk indicators</h4>
                                        <ul>
                                          {selectedScan.risk_indicators.map((indicator, index) => (
                                            <li key={`${indicator}-${index}`}>
                                              {formatRiskIndicator(indicator)}
                                            </li>
                                          ))}
                                        </ul>
                                      </div>
                                    )}
                                    <div>
                                      <h4>Recommendations</h4>
                                      {selectedScan.recommendations.length > 0 ? (
                                        <ul>
                                          {selectedScan.recommendations.map((recommendation, index) => (
                                            <li key={`${recommendation}-${index}`}>{recommendation}</li>
                                          ))}
                                        </ul>
                                      ) : (
                                        <p className="result-empty">No recommendations were recorded.</p>
                                      )}
                                    </div>
                                  </div>
                                  {Object.keys(selectedScan.details).length > 0 && (
                                    <dl className="history-record-details">
                                      {Object.entries(selectedScan.details).map(([key, value]) => (
                                        <div key={key}>
                                          <dt>{key.replaceAll('_', ' ')}</dt>
                                          <dd>
                                            {typeof value === 'string' || typeof value === 'number'
                                              ? value
                                              : '—'}
                                          </dd>
                                        </div>
                                      ))}
                                    </dl>
                                  )}
                                </>
                              )}
                            </section>
                          )}
                        </article>
                      ))}
                    </div>
                  ) : (
                    <p className="history-status">No scans are available on this page.</p>
                  )}

                  <div className="history-pagination">
                    <span>
                      Showing {historyOffset + 1}–{Math.min(historyOffset + history.items.length, history.total)} of {history.total}
                    </span>
                    <div>
                      <button
                        className="button button-outline button-small"
                        disabled={historyLoading || historyOffset === 0}
                        onClick={() => void loadHistoryPage(Math.max(0, historyOffset - SCAN_HISTORY_PAGE_SIZE))}
                        type="button"
                      >
                        Previous
                      </button>
                      <button
                        className="button button-outline button-small"
                        disabled={historyLoading || historyOffset + history.items.length >= history.total}
                        onClick={() => void loadHistoryPage(historyOffset + SCAN_HISTORY_PAGE_SIZE)}
                        type="button"
                      >
                        Next
                      </button>
                    </div>
                  </div>
                </>
              )}
              <p className="history-privacy-note">
                Original messages, full URLs, extracted screenshot text, and image files are not included in saved history.
              </p>
            </section>
          </div>
        </section>

        <section aria-labelledby="features-title" className="features-section section-padding" id="about">
          <div className="page-container">
            <div className="section-heading centered-heading">
              <div className="eyebrow"><span className="eyebrow-dash" /> A CALMER WAY TO STAY SAFE</div>
              <h2 id="features-title">Protection that starts with awareness.</h2>
              <p>Simple tools to help you think twice about the things that ask you to act fast.</p>
            </div>
            <div className="feature-grid">
              <article className="feature-card">
                <div className="feature-icon"><MessageIcon /></div>
                <span className="feature-number">01</span>
                <h3>AI Message Detection</h3>
                <p>Review suspicious texts, emails, and direct messages for common scam warning signs.</p>
                <a className="feature-link" href="#message-scanner">
                  Check a message <ArrowIcon />
                </a>
              </article>
              <article className="feature-card">
                <div className="feature-icon feature-icon-green"><LinkIcon /></div>
                <span className="feature-number">02</span>
                <h3>URL Pattern Review</h3>
                <p>Review basic web-address patterns before deciding what to do. Results do not confirm a URL is safe or malicious.</p>
                <a className="feature-link" href="#url-scanner">
                  Scan a URL <ArrowIcon />
                </a>
              </article>
              <article className="feature-card">
                <div className="feature-icon feature-icon-blue"><ImageIcon /></div>
                <span className="feature-number">03</span>
                <h3>Screenshot Scanning</h3>
                <p>Extract and review message text from a screenshot before scanning it for common warning signs.</p>
                <a className="feature-link" href="#screenshot-scanner">
                  Scan a screenshot <ArrowIcon />
                </a>
              </article>
            </div>
            <p className="feature-note">
              <span className="note-dot" />
              Screenshot text extraction does not verify links or guarantee a message is safe. URL results are limited to basic patterns.
            </p>
          </div>
        </section>

        <section aria-labelledby="steps-title" className="steps-section section-padding" id="how-it-works">
          <div className="page-container steps-layout">
            <div className="steps-intro">
              <div className="eyebrow"><span className="eyebrow-dash" /> HOW IT WORKS</div>
              <h2 id="steps-title">A smarter pause<br />in three steps.</h2>
              <p>Scams often rely on urgency. Taking a moment to check can help you make a more informed decision.</p>
              <a className="button button-outline" href="#message-scanner">
                Try the message scanner <ArrowIcon />
              </a>
            </div>
            <ol className="steps-list">
              <li>
                <span className="step-number">01</span>
                <div className="step-content">
                  <h3>Submit suspicious content.</h3>
                  <p>Share a message or other content you want to look at more closely.</p>
                </div>
                <span aria-hidden="true" className="step-icon"><MessageIcon /></span>
              </li>
              <li>
                <span className="step-number">02</span>
                <div className="step-content">
                  <h3>AI analyzes available evidence.</h3>
                  <p>When connected, the service can review signals like unusual requests or links.</p>
                </div>
                <span aria-hidden="true" className="step-icon"><ScanIcon /></span>
              </li>
              <li>
                <span className="step-number">03</span>
                <div className="step-content">
                  <h3>Review indicators and next steps.</h3>
                  <p>Use clear, practical guidance to decide what you’d like to do next.</p>
                </div>
                <span aria-hidden="true" className="step-icon"><ShieldIcon /></span>
              </li>
            </ol>
          </div>
        </section>

        <section aria-label="Get started" className="closing-section">
          <div className="page-container closing-inner">
            <div className="closing-icon"><ShieldIcon /></div>
            <div>
              <h2>When in doubt, take a second look.</h2>
              <p>Build safer digital habits, one check at a time.</p>
            </div>
            <a className="button button-primary" href="#message-scanner">
              Get Started <ArrowIcon />
            </a>
          </div>
        </section>
      </main>

      <footer className="site-footer">
        <div className="page-container">
          <div className="footer-main">
            <div className="footer-brand-block">
              <a aria-label="ScamShield AI home" className="brand" href="#home">
                <span className="brand-mark"><ShieldIcon /></span>
                <span className="brand-name">ScamShield <span>AI</span></span>
              </a>
              <p>Helping you make more informed decisions in a world of online scams.</p>
            </div>
            <nav aria-label="Footer navigation" className="footer-nav">
              <span className="footer-nav-title">Explore</span>
              <a href="#message-scanner">Message Scanner</a>
              <a href="#screenshot-scanner">Screenshot Scanner</a>
              <a href="#url-scanner">URL Scanner</a>
              <a href="#scan-history">Scan History</a>
              <a href="#how-it-works">How It Works</a>
              <a href="#privacy">Privacy</a>
            </nav>
            <div className="footer-disclaimer" id="privacy">
              <span className="footer-nav-title">Privacy &amp; responsible use</span>
              <p>ScamShield AI is an informational tool, not a guarantee of safety. Never share passwords, payment details, or other sensitive information. When in doubt, verify through an official channel.</p>
            </div>
          </div>
          <div className="footer-bottom">
            <span>© {CURRENT_YEAR} ScamShield AI</span>
            <span>Privacy-minded by design. Stay thoughtful online.</span>
          </div>
        </div>
      </footer>
    </>
  )
}

export default App
