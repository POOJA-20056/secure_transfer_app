import { useState } from 'react'
import { Bar, BarChart, CartesianGrid, Legend, Tooltip, XAxis, YAxis, ResponsiveContainer } from 'recharts'
import './App.css'

function App() {
  const [mode, setMode] = useState<'send' | 'receive'>('send')
  const [message, setMessage] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [sensitivity, setSensitivity] = useState<'Normal' | 'Confidential' | 'Highly Confidential'>('Normal')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  const [encMeta, setEncMeta] = useState<{
    size: number
    encryption_time: number
    sensitivity: string
  } | null>(null)

  const [decResult, setDecResult] = useState<{
    status: string
    message: string
    signature?: string
    trust_score?: number
    is_text?: boolean
    data?: string
    decryption_time?: number
  } | null>(null)

  const [comparison, setComparison] = useState<{
    algorithms: string[]
    encryption_time: number[]
    decryption_time: number[]
    best_algorithm: string
    reason: string
  } | null>(null)

  const backendUrl =
    `${window.location.protocol}//${window.location.hostname}:8000`

  const handleEncrypt = async () => {
    setError(null)
    setSuccess(null)
    setLoading(true)
    try {
      const formData = new FormData()
      if (message) formData.append('message', message)
      if (file) formData.append('file', file)
      formData.append('sensitivity', sensitivity)

      const res = await fetch(`${backendUrl}/api/encrypt`, {
        method: 'POST',
        body: formData,
      })

      if (!res.ok) {
        const err = await res.json().catch(() => null)
        throw new Error(err?.detail || 'Encryption failed')
      }

      const data = await res.json()
      setSuccess(data.message || 'Encryption Successful')
      setEncMeta(data.meta)
      setDecResult(null)

      // Trigger download of .dat file
      const b64 = data.encrypted_file_content as string
      const filename = (data.encrypted_file_name as string) || 'encrypted.dat'
      const blob = b64
        ? new Blob([Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))], { type: 'application/octet-stream' })
        : null
      if (blob) {
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = filename
        document.body.appendChild(a)
        a.click()
        a.remove()
        URL.revokeObjectURL(url)
      }
    } catch (e: any) {
      if (e instanceof TypeError) {
        setError('Cannot reach backend. Please check that uvicorn is running on port 8000.')
      } else {
        setError(e.message || 'Something went wrong')
      }
    } finally {
      setLoading(false)
    }
  }

  const handleDecrypt = async () => {
    if (!file) {
      setError('Please upload an encrypted .dat file.')
      return
    }
    setError(null)
    setSuccess(null)
    setLoading(true)
    try {
      const formData = new FormData()
      formData.append('file', file)

      const res = await fetch(`${backendUrl}/api/decrypt`, {
        method: 'POST',
        body: formData,
      })

      if (!res.ok) {
        throw new Error('Decryption failed')
      }

      const data = await res.json()
      setDecResult({
        status: data.status,
        message: data.message,
        signature: data.signature,
        trust_score: data.trust_score,
        is_text: data.is_text,
        data: data.data,
        decryption_time: data.meta?.decryption_time,
      })
    } catch (e: any) {
      if (e instanceof TypeError) {
        setError('Cannot reach backend. Please check that uvicorn is running on port 8000.')
      } else {
        setError(e.message || 'Something went wrong')
      }
    } finally {
      setLoading(false)
    }
  }

  const handleCompare = async () => {
    setError(null)
    setSuccess(null)
    setLoading(true)
    try {
      // Use the current file's payload size for comparison if available
      const payloadSize =
        encMeta?.size ??
        (decResult?.data ? new TextEncoder().encode(decResult.data).length : undefined)

      const url = new URL(`${backendUrl}/api/compare`)
      if (payloadSize !== undefined) {
        url.searchParams.set('size', String(payloadSize))
      }

      const res = await fetch(url.toString())
      if (!res.ok) throw new Error('Comparison failed')
      const data = await res.json()
      setComparison({
        algorithms: data.algorithms,
        encryption_time: data.encryption_time,
        decryption_time: data.decryption_time,
        best_algorithm: data.best_algorithm,
        reason: data.reason,
      })
    } catch (e: any) {
      if (e instanceof TypeError) {
        setError('Cannot reach backend. Please check that uvicorn is running on port 8000.')
      } else {
        setError(e.message || 'Something went wrong')
      }
    } finally {
      setLoading(false)
    }
  }

  const canShowGraph = decResult?.status === 'success'

  const comparisonData =
    comparison &&
    (() => {
      const idx = comparison.algorithms.indexOf(comparison.best_algorithm)
      if (idx === -1) return null
      return [
        {
          name: comparison.best_algorithm,
          encryption: comparison.encryption_time[idx],
          decryption: comparison.decryption_time[idx],
        },
      ]
    })()

  return (
    <div className="app-root">
      <header className="app-header">
        <div>
          <h1>Secure Transfer Console</h1>
          <p>End‑to‑end encrypted files and messages</p>
        </div>
        <div className="mode-toggle">
          <button
            className={mode === 'send' ? 'mode-btn active' : 'mode-btn'}
            onClick={() => setMode('send')}
          >
            Sender
          </button>
          <button
            className={mode === 'receive' ? 'mode-btn active' : 'mode-btn'}
            onClick={() => setMode('receive')}
          >
            Receiver
          </button>
        </div>
      </header>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      <main className="layout">
        <section className="panel">
          {mode === 'send' ? (
            <>
              <h2>Sender Panel</h2>
              <label className="field">
                <span>Message</span>
                <textarea
                  value={message}
                  onChange={(e) => setMessage(e.target.value)}
                  placeholder="Type a secure message..."
                  rows={4}
                />
              </label>

              <label className="field">
                <span>File (optional)</span>
                <input
                  type="file"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                />
              </label>

              <label className="field">
                <span>Sensitivity</span>
                <select
                  value={sensitivity}
                  onChange={(e) => setSensitivity(e.target.value as any)}
                >
                  <option value="Normal">Normal</option>
                  <option value="Confidential">Confidential</option>
                  <option value="Highly Confidential">Highly Confidential</option>
                </select>
              </label>

              <button
                className="primary-btn"
                onClick={handleEncrypt}
                disabled={loading}
              >
                {loading ? 'Processing…' : 'Encrypt & Save .dat'}
              </button>
            </>
          ) : (
            <>
              <h2>Receiver Panel</h2>
              <label className="field">
                <span>Encrypted File (.dat)</span>
                <input
                  type="file"
                  accept=".dat"
                  onChange={(e) => setFile(e.target.files?.[0] ?? null)}
                />
              </label>

              <button
                className="primary-btn"
                onClick={handleDecrypt}
                disabled={loading}
              >
                {loading ? 'Processing…' : 'Decrypt & Verify'}
              </button>
            </>
          )}
        </section>

        <section className="panel">
          <h2>Transfer Details</h2>
          {!encMeta && !decResult && (
            <p className="muted">No data yet. Run an encryption or decryption.</p>
          )}
          {(encMeta || decResult) && (
            <>
              <div className="stats-row">
                {encMeta && (
                  <>
                    <div className="stat">
                      <span className="label">Payload size</span>
                      <span className="value">{encMeta.size} bytes</span>
                    </div>
                  <div className="stat">
                      <span className="label">Encryption time</span>
                      <span className="value">
                        {encMeta.encryption_time.toFixed(4)} s
                      </span>
                  </div>
                    <div className="stat">
                      <span className="label">Sensitivity</span>
                      <span className="value">{encMeta.sensitivity}</span>
                    </div>
                  </>
                )}
                {decResult?.decryption_time !== undefined && (
                  <div className="stat">
                    <span className="label">Decryption time</span>
                    <span className="value">
                      {decResult.decryption_time.toFixed(4)} s
                    </span>
                  </div>
                )}
              </div>

              {decResult && (
                <>
                  <div
                    className={
                      decResult.status === 'success'
                        ? 'alert alert-success'
                        : 'alert alert-error'
                    }
                  >
                    {decResult.message}
                  </div>

                  {decResult.status === 'success' && (
                    <>
                      <div className="field">
                        <span>Decrypted Content</span>
                        <div className="decoded-box">
                          {decResult.is_text ? (
                            <pre>{decResult.data}</pre>
                          ) : (
                            <code>(Binary content, base64)</code>
                          )}
                        </div>
                      </div>
                    </>
                  )}
                </>
              )}
            </>
          )}
        </section>
      </main>

      <section className="panel comparison-panel">
        <div className="comparison-header">
          <div>
            <h2>Algorithm Comparison</h2>
            <p className="muted">
              Compare AES, Blowfish and RSA based on encryption / decryption time.
            </p>
          </div>
          <button
            className="primary-btn"
            onClick={handleCompare}
            disabled={loading || !canShowGraph}
          >
            Compare Algorithms
          </button>
        </div>

        {!canShowGraph && (
          <p className="muted">
            Run a successful decryption first to enable comparison.
          </p>
        )}

        {canShowGraph && comparison && comparisonData && (
          <>
            <div className="chart-container">
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={comparisonData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                  <XAxis dataKey="name" stroke="#9ca3af" />
                  <YAxis stroke="#9ca3af" />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="encryption" fill="#6366f1" name="Encryption (s)" />
                  <Bar dataKey="decryption" fill="#22c55e" name="Decryption (s)" />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <p className="chart-caption">
              Best Algorithm: <strong>{comparison.best_algorithm}</strong> —{' '}
              {comparison.reason}
            </p>
          </>
        )}
      </section>
    </div>
  )
}

export default App
