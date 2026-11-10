import { useState } from 'react'
import './App.css'

const MAX_MESSAGE_LENGTH = 2000
const CURRENT_YEAR = new Date().getFullYear()

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

function App() {
  const [message, setMessage] = useState('')
  const [status, setStatus] = useState('')
  const [menuOpen, setMenuOpen] = useState(false)

  function handleAnalyze() {
    setStatus(
      message.trim()
        ? 'AI message analysis will be available after backend integration. Your message has not been analyzed.'
        : 'Enter a message above to get started. AI analysis will be available after backend integration.',
    )
  }

  function handleClear() {
    setMessage('')
    setStatus('')
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
            <a href="#url-scanner" onClick={closeMenu}>URL Scanner</a>
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
                <span className="privacy-label"><ShieldIcon /> Your message stays in this browser</span>
              </div>
              <label className="visually-hidden" htmlFor="message-input">
                Suspicious message to check
              </label>
              <textarea
                id="message-input"
                maxLength={MAX_MESSAGE_LENGTH}
                onChange={(event) => {
                  setMessage(event.target.value)
                  setStatus('')
                }}
                placeholder="Paste a suspicious text, email, or direct message here..."
                value={message}
              />
              <div className="scanner-controls">
                <span aria-live="polite" className="character-count">
                  {message.length} / {MAX_MESSAGE_LENGTH} characters
                </span>
                <div className="scanner-buttons">
                  <button className="button button-clear" onClick={handleClear} type="button">
                    Clear
                  </button>
                  <button className="button button-primary analyze-button" onClick={handleAnalyze} type="button">
                    <ScanIcon /> Analyze Message <ArrowIcon />
                  </button>
                </div>
              </div>
              {status && <p className="scanner-status" role="status">{status}</p>}
              <p className="scanner-disclaimer">
                No message is sent or analyzed. Connect a backend to enable AI-powered checks.
              </p>
            </div>
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
              <article className="feature-card" id="url-scanner">
                <div className="feature-icon feature-icon-green"><LinkIcon /></div>
                <span className="feature-number">02</span>
                <h3>Phishing URL Detection</h3>
                <p>Learn to spot unexpected links and deceptive web addresses before you click.</p>
                <a className="feature-link" href="#how-it-works">
                  Learn how to check <ArrowIcon />
                </a>
              </article>
              <article className="feature-card">
                <div className="feature-icon feature-icon-blue"><ImageIcon /></div>
                <span className="feature-number">03</span>
                <h3>Screenshot Scanning</h3>
                <p>Get guidance on what to look for in screenshots of suspicious conversations or offers.</p>
                <a className="feature-link" href="#how-it-works">
                  Explore the process <ArrowIcon />
                </a>
              </article>
            </div>
            <p className="feature-note">
              <span className="note-dot" />
              These capabilities are product goals; automated analysis is not enabled yet.
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
              <a href="#url-scanner">URL Scanner</a>
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
