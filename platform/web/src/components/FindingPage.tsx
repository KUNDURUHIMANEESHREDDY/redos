import React, { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import axios from 'axios'

const FindingPage: React.FC = () => {
  const navigate = useNavigate()
  const [finding, setFinding] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const { organizationId } = useAuth()

  useEffect(() => {
    const loadFinding = async () => {
      const findingId = new URLSearchParams(window.location.search).get('id')
      if (!findingId) {
        setError('No finding ID specified')
        setLoading(false)
        return
      }

      try {
        const response = await axios.get(`/api/v1/findings/${findingId}`, {
          headers: { 
            'Authorization': `Bearer ${localStorage.getItem('redos_token')}` 
          },
          params: { orgId: organizationId }
        })
        setFinding(response.data)
      } catch (err) {
        setError('Failed to load finding')
        console.error(err)
      } finally {
        setLoading(false)
      }
    }

    loadFinding()
  }, [navigate, organizationId])

  if (loading) return '<div>Loading...</div>'
  if (error) return `<div class="error">${error}</div>`

  if (!finding) return '<div>Finding not found</div>'

  return (
    <div className="finding-page">
      <div className="finding-card">
        {/* Severity badge */}
        <div className={`severity-badge ${finding.severity.toLowerCase()}`}>
          {finding.severity}
        </div>

        <h1>{finding.title}</h1>

        {/* CRITICAL indicator */}
        {finding.severity === 'CRITICAL' && (
          <div className="critical-indicator">
            CRITICAL
          </div>
        )}

        {/* Target & Attack info */}
        <div className="info-section">
          <div className="info-row">
            <span className="info-label">Target</span>
            <span className="info-value">{finding.targetName || 'N/A'}</span>
          </div>
          <div className="info-row">
            <span className="info-label">Attack</span>
            <span className="info-value">{finding.attackName || 'N/A'}</span>
          </div>
          <div className="info-row">
            <span className="info-label">First discovered</span>
            <span className="info-value">
              {finding.discoveredAt ? new Date(finding.discoveredAt).toLocaleDateString() : 'N/A'}
            </span>
          </div>
          <div className="info-row">
            <span className="info-label">Last reproduced</span>
            <span className="info-value">
              {finding.reproducedAt ? new Date(finding.reproducedAt).toLocaleString() : 'N/A'}
            </span>
          </div>
        </div>

        {/* Attack Path */}
        <div className="attack-path-section">
          <h3>Attack Path</h3>
          <div className="attack-path-chain">
            {finding.attackPath?.map((step: string, index: number) => (
              <div key={index} className="attack-step">
                {step}
              </div>
            ))}
          </div>
        </div>

        {/* Evidence */}
        <div className="evidence-section">
          <h3>Evidence</h3>
          <div className="evidence-tabs">
            <button className="evidence-tab active" data-type="model-output">Model Output</button>
            <button className="evidence-tab" data-type="retrieved-document">Retrieved Documents</button>
            <button className="evidence-tab" data-type="tool-call">Tool Calls</button>
            <button className="evidence-tab" data-type="execution-trace">Execution Trace</button>
          </div>

          <div className="evidence-content" id="model-output">
            <pre>{finding.modelOutput || 'No model output available'}</pre>
          </div>

          <div className="evidence-content" id="retrieved-document">
            {finding.retrievedDocuments?.map((doc: any, i: number) => (
              <div key={i} className="document-item">
                <h4>Document {i + 1}</h4>
                <p>{doc.title || 'Untitled'}</p>
                <p>{doc.summary || 'No summary available'}</p>
              </div>
            )) || 'No documents available'}
          </div>

          <div className="evidence-content" id="tool-call">
            {finding.toolCalls?.map((call: any, i: number) => (
              <div key={i} className="tool-call-item">
                <strong>Call {i + 1}:</strong> {call.type || 'unknown'}
                <pre>{JSON.stringify(call.data, null, 2)}</pre>
              </div>
            )) || 'No tool calls available'}
          </div>

          <div className="evidence-content" id="execution-trace">
            {finding.executionTrace?.map((trace: any, i: number) => (
              <div key={i} className="trace-item">
                <span className="trace-step">Step {i + 1}</span>
                <pre>{JSON.stringify(trace, null, 2)}</pre>
              </div>
            )) || 'No execution trace available'}
          </div>
        </div>

        {/* Root Cause */}
        <div className="root-cause-section">
          <h3>Root Cause</h3>
          <p>{finding.rootCause || 'Not specified'}</p>
        </div>

        {/* Remediation */}
        <div className="remediation-section">
          <h3>Remediation</h3>
          <p>{finding.remediation || 'Not specified'}</p>
        </div>

        {/* Regression Test */}
        <div className="regression-test-section">
          <h3>Regression Test</h3>
          <button className="run-test-btn" onClick={() => {
            // TODO: Run regression test
            alert('Regression test triggered')
          }}>
            Run Test
          </button>
        </div>
      </div>
    </div>
  )
}

export default FindingPage