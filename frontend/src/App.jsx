import { useEffect, useMemo, useRef, useState } from 'react';

const API_BASE = 'http://localhost:5000/api';
const API_HEALTH_URL = `${API_BASE}/health`;
const API_STATS_URL = `${API_BASE}/ml/stats`;
const API_ANALYZE_URL = `${API_BASE}/ml/analyze-stack`;

const starter = {
  id: crypto.randomUUID(),
  role: 'bot',
  text: 'Cyber ML console online. Enter a tech stack and version to get a dataset-backed output.'
};

const quickReplies = [
  'pan-os 10.1.6',
  'pan-os 9.0.17',
  'wordpress 6.4.3',
  'nginx 1.24.0'
];

const stackSuggestions = [
  { product: 'pan-os', version: '10.1.6' },
  { product: 'pan-os', version: '9.0.17' },
  { product: 'wordpress', version: '6.4.3' },
  { product: 'nginx', version: '1.24.0' }
];

async function analyzeStack(product, version) {
  const response = await fetch(API_ANALYZE_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ product, version })
  });

  if (!response.ok) {
    const payload = await response.json().catch(() => null);
    throw new Error(payload?.error || 'API request failed');
  }

  return response.json();
}

export default function App() {
  const [messages, setMessages] = useState([starter]);
  const [product, setProduct] = useState('pan-os');
  const [version, setVersion] = useState('10.1.6');
  const [typing, setTyping] = useState(false);
  const [loadingMeta, setLoadingMeta] = useState(true);
  const [connection, setConnection] = useState({ ok: false, records: 0, uniqueCves: 0 });
  const [stats, setStats] = useState({ records: 0, uniqueCves: 0, labelDistribution: {} });
  const [result, setResult] = useState(null);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    let active = true;

    async function loadMeta() {
      try {
        const [healthResponse, statsResponse] = await Promise.all([
          fetch(API_HEALTH_URL),
          fetch(API_STATS_URL)
        ]);

        const health = healthResponse.ok ? await healthResponse.json() : null;
        const statsPayload = statsResponse.ok ? await statsResponse.json() : null;

        if (!active) {
          return;
        }

        if (health) {
          setConnection({
            ok: Boolean(health.ok),
            records: health.records || 0,
            uniqueCves: health.uniqueCves || 0
          });
        }

        if (statsPayload) {
          setStats({
            records: statsPayload.records || 0,
            uniqueCves: statsPayload.uniqueCves || 0,
            labelDistribution: statsPayload.labelDistribution || {}
          });
        }
      } catch {
        if (active) {
          setConnection({ ok: false, records: 0, uniqueCves: 0 });
          setStats({ records: 0, uniqueCves: 0, labelDistribution: {} });
        }
      } finally {
        if (active) {
          setLoadingMeta(false);
        }
      }
    }

    loadMeta();

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [messages, typing]);

  const labelEntries = useMemo(
    () => Object.entries(stats.labelDistribution).sort((left, right) => right[1] - left[1]),
    [stats.labelDistribution]
  );
  const topLabel = labelEntries[0]?.[0] || 'UNKNOWN';

  async function runAnalysis(rawProduct, rawVersion) {
    const nextProduct = rawProduct.trim().toLowerCase();
    const nextVersion = rawVersion.trim();
    if (!nextProduct || !nextVersion) {
      return;
    }

    const userMessage = {
      id: crypto.randomUUID(),
      role: 'user',
      text: `${nextProduct} ${nextVersion}`
    };

    setMessages((prev) => [...prev, userMessage]);
    setTyping(true);

    window.setTimeout(async () => {
      let payload;
      try {
        payload = await analyzeStack(nextProduct, nextVersion);
      } catch {
        payload = {
          predicted_label: 'UNKNOWN',
          confidence: 0,
          matchedRows: 0,
          max_cvss: 0,
          sample_cves: [],
          summary: 'Backend unavailable. The console is running in offline mode.'
        };
      }

      setResult(payload);

      const botMessage = {
        id: crypto.randomUUID(),
        role: 'bot',
        kind: payload.response_text ? 'report' : 'text',
        text:
          payload.response_text ||
          `${payload.summary} Predicted label: ${payload.predicted_label}. Confidence: ${Math.round((payload.confidence || 0) * 100)}%.`
      };
      setMessages((prev) => [...prev, botMessage]);
      setTyping(false);
    }, 450);
  }

  function onSubmit(event) {
    event.preventDefault();
    runAnalysis(product, version);
  }

  const hasResult = Boolean(result);

  return (
    <div className="cyber-shell">
      <div className="grid-overlay" aria-hidden="true" />
      <header className="hud hud-top">
        <div>
          <h1>CYBER STACK INTEL CENTER</h1>
          <p>Enter a tech stack and version to receive a dataset-backed model output</p>
        </div>
        <div className={`status-pill ${connection.ok ? 'online' : 'offline'}`}>
          {loadingMeta ? 'SYNCING' : connection.ok ? 'LIVE BACKEND' : 'OFFLINE MODE'}
        </div>
      </header>

      <section className="dashboard-cards" aria-label="Dataset summary">
        <article className="stat-card highlight">
          <span className="stat-label">dataset rows</span>
          <strong>{connection.records || stats.records || '—'}</strong>
          <p>Rows loaded from your ML table for training and stack lookup.</p>
        </article>
        <article className="stat-card">
          <span className="stat-label">unique cves</span>
          <strong>{connection.uniqueCves || stats.uniqueCves || '—'}</strong>
          <p>Distinct vulnerability IDs linked to product/version records.</p>
        </article>
        <article className="stat-card">
          <span className="stat-label">top label</span>
          <strong>{topLabel}</strong>
          <p>Most common class in the current label distribution.</p>
        </article>
        <article className="stat-card">
          <span className="stat-label">engine mode</span>
          <strong>{connection.ok ? 'LIVE' : 'FALLBACK'}</strong>
          <p>{connection.ok ? 'Connected to the local ML backend.' : 'Using local fallback responses.'}</p>
        </article>
      </section>

      <main className="panel split-layout">
        <section className="terminal-stack">
          <div className="section-head">
            <div>
              <span className="section-kicker">interactive intelligence</span>
              <h2>Stack-to-label analyzer</h2>
            </div>
            <div className="section-note">Provide product and version to inspect the likely output.</div>
          </div>

          <section className="messages" aria-live="polite">
            {messages.map((message) => (
              <article key={message.id} className={`bubble ${message.role}`}>
                <span className="tag">{message.role === 'user' ? 'OPERATOR' : 'AI'}</span>
                {message.kind === 'report' ? (
                  <pre className="report-text">{message.text}</pre>
                ) : (
                  <p>{message.text}</p>
                )}
              </article>
            ))}

            {typing ? (
              <article className="bubble bot typing" role="status" aria-label="AI is typing">
                <span className="tag">AI</span>
                <p>Analyzing stack signature...</p>
              </article>
            ) : null}
            <div ref={messagesEndRef} />
          </section>

          <aside className="quick-actions">
            {quickReplies.map((item) => (
              <button
                key={item}
                type="button"
                onClick={() => {
                  const parts = item.split(' ');
                  const nextProduct = parts[0];
                  const nextVersion = parts.slice(1).join(' ');
                  setProduct(nextProduct);
                  setVersion(nextVersion);
                  runAnalysis(nextProduct, nextVersion);
                }}
              >
                {item}
              </button>
            ))}
          </aside>

          <form className="composer" onSubmit={onSubmit}>
            <input
              value={product}
              onChange={(event) => setProduct(event.target.value)}
              placeholder="tech stack"
              aria-label="Tech stack input"
            />
            <input
              value={version}
              onChange={(event) => setVersion(event.target.value)}
              placeholder="version"
              aria-label="Version input"
            />
            <button type="submit">Analyze</button>
          </form>
        </section>

        <aside className="insight-rail">
          <section className="insight-card">
            <div className="section-head compact">
              <div>
                <span className="section-kicker">stack input</span>
                <h2>Analyze one tech stack</h2>
              </div>
            </div>
            <form className="cve-form" onSubmit={onSubmit}>
              <input
                value={product}
                onChange={(event) => setProduct(event.target.value)}
                placeholder="pan-os"
                aria-label="Tech stack lookup input"
              />
              <input
                value={version}
                onChange={(event) => setVersion(event.target.value)}
                placeholder="10.1.6"
                aria-label="Version lookup input"
              />
              <button type="submit">Run model</button>
            </form>
            <div className="suggestion-row">
              {stackSuggestions.map((item) => (
                <button
                  key={`${item.product}-${item.version}`}
                  type="button"
                  onClick={() => {
                    setProduct(item.product);
                    setVersion(item.version);
                  }}
                >
                  {item.product} {item.version}
                </button>
              ))}
            </div>
          </section>

          <section className="insight-card result-card">
            <div className="section-head compact">
              <div>
                <span className="section-kicker">model output</span>
                <h2>Predicted result</h2>
              </div>
            </div>
            {hasResult ? (
              <div>
                <div className="result-grid">
                  <div>
                    <span className="result-label">label</span>
                    <strong>{result.predicted_label}</strong>

                <div className="result-wide">
                  <span className="result-label">exact / closest matches</span>
                  {(result.detailed_matches || []).length > 0 ? (
                    <div className="detail-list">
                      {result.detailed_matches.map((item) => (
                        <article key={`${item.cve_id}-${item.version_rule}`} className="detail-card">
                          <p><strong>CVE:</strong> {item.cve_id}</p>
                          <p><strong>Product:</strong> {item.product}</p>
                          <p><strong>Version Rule:</strong> {item.version_rule}</p>
                          <p><strong>CVSS:</strong> {item.cvss}</p>
                          <p><strong>Risk:</strong> {item.risk}</p>
                        </article>
                      ))}
                    </div>
                  ) : (
                    <p>No exact or closest matches found.</p>
                  )}
                </div>
                  </div>
                  <div>
                    <span className="result-label">confidence</span>
                    <strong>{Math.round((result.confidence || 0) * 100)}%</strong>
                  </div>
                  <div>
                    <span className="result-label">matched rows</span>
                    <strong>{result.matchedRows}</strong>
                  </div>
                  <div>
                    <span className="result-label">max cvss</span>
                    <strong>{result.max_cvss || '—'}</strong>
                  </div>
                  <div className="result-wide">
                    <span className="result-label">sample cves</span>
                    <p>{(result.sample_cves || []).length > 0 ? result.sample_cves.join(', ') : 'No direct match found'}</p>
                  </div>
                </div>

                <div className="result-wide raw-block">
                  <span className="result-label">raw model response</span>
                  <pre>{JSON.stringify(result, null, 2)}</pre>
                </div>
              </div>
            ) : (
              <p className="muted-copy">Run the analyzer to see the output for a stack and version.</p>
            )}
          </section>

          <section className="insight-card">
            <div className="section-head compact">
              <div>
                <span className="section-kicker">ml insight</span>
                <h2>Label distribution</h2>
              </div>
            </div>
            <div className="bars">
              {labelEntries.length > 0 ? (
                labelEntries.slice(0, 5).map(([label, count]) => {
                  const maxCount = labelEntries[0][1] || 1;
                  const width = Math.max((count / maxCount) * 100, 10);
                  return (
                    <div key={label} className="bar-row">
                      <div className="bar-meta">
                        <span>{label}</span>
                        <span>{count}</span>
                      </div>
                      <div className="bar-track">
                        <div className="bar-fill" style={{ width: `${width}%` }} />
                      </div>
                    </div>
                  );
                })
              ) : (
                <p className="muted-copy">Stats will appear here once the backend responds.</p>
              )}
            </div>
          </section>

          <section className="insight-card">
            <div className="section-head compact">
              <div>
                <span className="section-kicker">smart prompts</span>
                <h2>What to ask</h2>
              </div>
            </div>
            <ul className="prompt-list">
              <li>Enter a product name and version to see the model output.</li>
              <li>Use the sample chips to test known tech stacks quickly.</li>
              <li>Ask for dataset stats to verify how much data is available for training.</li>
            </ul>
          </section>
        </aside>
      </main>
    </div>
  );
}