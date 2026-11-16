import { useEffect, useState } from "react";

import { api } from "../api/client";
import type { InstallerInfoResponse } from "../api/client";

/**
 * The employee-facing enrollment page, served at /enroll.
 *
 * This is the only route in the dashboard an unauthenticated visitor is meant
 * to reach, and it is deliberately austere about what it touches: one public
 * endpoint, `GET /api/v1/installer`, and nothing else. No admin API, no
 * session, no capability check. An employee arriving here has no UbuntuGuard
 * account and should never see one being asked for.
 *
 * Two editorial rules, both of which this page exists to respect:
 *
 * It must not overstate compatibility. The server reports the releases the
 * agent is written FOR and the releases it has been RUN ON as two separate
 * lists, and the second is empty. This page shows both, because an employee
 * deciding whether to install deserves to know which it is.
 *
 * It must not ask for the token here. The token is typed into the installer on
 * the employee's own machine. A web form that collected one would put a
 * single-use credential into a browser, a server log and a form history for no
 * reason at all.
 */

const DOWNLOAD_PATH = "/api/v1/installer/download";

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function EnrollPage() {
  const [installer, setInstaller] = useState<InstallerInfoResponse | null>(null);
  /** Null while loading, a string once we know the download is unavailable. */
  const [unavailable, setUnavailable] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const info = await api.installerInfo();
        if (!cancelled) setInstaller(info);
      } catch (caught) {
        // The server says 503 with a reason when no installer is published.
        // Shown as prose to the employee rather than as an error code: they
        // cannot fix it, and the only useful action is to tell somebody.
        if (!cancelled) {
          setUnavailable(
            caught instanceof Error && caught.message
              ? caught.message
              : "The agent download is not available on this server.",
          );
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  function copy(label: string, value: string) {
    void navigator.clipboard?.writeText(value).then(() => {
      setCopied(label);
      window.setTimeout(() => setCopied(null), 2000);
    });
  }

  const verifyCommand = installer
    ? `sha256sum ${installer.filename}`
    : "sha256sum ubuntuguard-agent-installer.sh";
  const runCommand = installer ? `./${installer.filename}` : "./ubuntuguard-agent-installer.sh";

  return (
    <div className="enroll-shell">
      <header className="enroll-head">
        <div className="brand large">
          <span className="brand-mark" aria-hidden="true" />
          <span>UbuntuGuard</span>
        </div>
        <p className="muted">Device enrollment for company Ubuntu laptops.</p>
      </header>

      <main className="enroll-body">
        {/* ----------------------------------------------------------------- */}
        {/* 1. Download                                                        */}
        {/* ----------------------------------------------------------------- */}
        <section className="card">
          <h2>Install the UbuntuGuard agent</h2>
          <p className="muted">
            Two things are needed: this installer, and a one-time enrollment token from
            your IT administrator. The installer does everything else.
          </p>

          {loading && <p className="muted small">Checking the available download…</p>}

          {unavailable && (
            <div className="banner error">
              <strong>The download is not available</strong>
              <p>{unavailable}</p>
              <p className="muted small">
                Nothing is wrong with your machine. Contact your IT administrator and
                quote this page.
              </p>
            </div>
          )}

          {installer && (
            <>
              <a className="download-button" href={DOWNLOAD_PATH} download>
                Download UbuntuGuard Agent
              </a>

              <dl className="download-facts">
                <div>
                  <dt>Version</dt>
                  <dd className="mono">{installer.agent_version}</dd>
                </div>
                <div>
                  <dt>Size</dt>
                  <dd>{formatSize(installer.size_bytes)}</dd>
                </div>
                <div>
                  <dt>Manages this device for</dt>
                  <dd className="mono">{installer.server_url}</dd>
                </div>
              </dl>
            </>
          )}
        </section>

        {/* ----------------------------------------------------------------- */}
        {/* 2. Supported platforms — stated honestly                           */}
        {/* ----------------------------------------------------------------- */}
        <section className="card">
          <h2>Supported systems</h2>
          <p className="muted">
            Ubuntu only. There is no macOS or Windows agent, and none is planned.
          </p>

          <ul className="feature-list">
            <li>
              Ubuntu, {installer ? installer.target_os_versions.join(" and ") : "22.04 and 24.04"}
            </li>
            <li>
              {installer ? installer.supported_arch.join(" or ") : "x86_64 or aarch64"} processor
            </li>
            <li>Python {installer?.minimum_python ?? "3.10"} or newer (already on Ubuntu)</li>
            <li>systemd, and an administrator password on this machine</li>
          </ul>

          {/*
            The distinction the whole project is careful about. `is_supported`
            and `is_validated_release` are separate in the agent for this
            reason, the server reports them as separate fields, and collapsing
            them here would undo all of it.
          */}
          {installer && installer.validated_os_versions.length === 0 && (
            <div className="banner warn">
              <div className="banner-head">
                <strong>Not yet tested on any Ubuntu release</strong>
                <code className="code-chip">unvalidated</code>
              </div>
              <p>
                The agent is written for Ubuntu{" "}
                {installer.target_os_versions.join(" and ")}, and reads only interfaces
                those releases provide. It has not yet been formally tested on either, so
                we are not claiming it works there — we are telling you what it was built
                for. If anything misbehaves after installing, tell your administrator.
              </p>
            </div>
          )}

          {installer && installer.validated_os_versions.length > 0 && (
            <p className="muted small">
              Tested on: {installer.validated_os_versions.join(", ")}.
            </p>
          )}
        </section>

        {/* ----------------------------------------------------------------- */}
        {/* 3. How to install                                                  */}
        {/* ----------------------------------------------------------------- */}
        <section className="card">
          <h2>How to install it</h2>
          <ol className="steps numbered">
            <li>
              <strong>Ask your administrator for an enrollment token.</strong> It is a
              long one-time code. It expires, and it works exactly once, so get it when
              you are ready to install.
            </li>
            <li>
              <strong>Download the installer</strong> using the button above. It saves to
              your Downloads folder.
            </li>
            <li>
              <strong>Open a terminal</strong> and go to that folder:
              <br />
              <code>cd ~/Downloads</code>
            </li>
            <li>
              <strong>Run it:</strong>
              <br />
              <code>{runCommand}</code>
              <br />
              You will be asked for your own login password first — that is Ubuntu asking
              permission to install a system service, and it is not the enrollment token.
            </li>
            <li>
              <strong>Paste the enrollment token</strong> when it asks. Nothing appears on
              screen as you type or paste; that is deliberate.
            </li>
          </ol>

          <p className="muted small">
            That is all. The agent starts straight away and comes back automatically after
            a reboot. You do not need to keep the installer or the token afterwards.
          </p>
        </section>

        {/* ----------------------------------------------------------------- */}
        {/* 4. Optional integrity check                                        */}
        {/* ----------------------------------------------------------------- */}
        {installer && (
          <section className="card">
            <h2>Checking the download (optional)</h2>
            <p className="muted">
              If you want to confirm the file you received is the file this server
              published, compare its fingerprint:
            </p>
            <div className="token-row">
              <code className="token">{verifyCommand}</code>
              <button type="button" className="ghost" onClick={() => copy("cmd", verifyCommand)}>
                {copied === "cmd" ? "Copied" : "Copy"}
              </button>
            </div>
            <p className="muted small">It should print exactly:</p>
            <div className="token-row">
              <code className="token break">{installer.sha256}</code>
              <button
                type="button"
                className="ghost"
                onClick={() => copy("sha", installer.sha256)}
              >
                {copied === "sha" ? "Copied" : "Copy"}
              </button>
            </div>
            <p className="muted small">
              The installer also checks itself: it verifies the agent embedded inside it
              before unpacking anything, and refuses to continue if that check fails. This
              manual step additionally covers the outer file.
            </p>
          </section>
        )}

        {/* ----------------------------------------------------------------- */}
        {/* 5. What this does to the machine                                   */}
        {/* ----------------------------------------------------------------- */}
        <section className="card">
          <h2>What this installs, and what it can see</h2>

          <h3 className="small-head">Your device gets its own identity</h3>
          <p className="muted">
            During enrollment your laptop generates its own private key, on the machine,
            and that key never leaves it — not during enrollment, not afterwards, not to
            this server. It is stored so that only the agent's own account can read it.
            What is sent to the server is a certificate request, which contains the
            matching public key and nothing secret.
          </p>

          <h3 className="small-head">The connection is authenticated both ways</h3>
          <p className="muted">
            After enrollment the agent presents its certificate on every request, and the
            server verifies it. There is no plaintext fallback and no shared password.
            Your enrollment token is used once, to prove you were authorised to enrol, and
            is then spent.
          </p>

          <h3 className="small-head">What is reported</h3>
          <ul className="feature-list">
            <li>Hostname, Ubuntu version, kernel and architecture</li>
            <li>That the machine is alive, roughly once a minute</li>
            <li>Agent version, and whether its certificate needs renewing</li>
          </ul>
          <p className="muted small">
            Not your files, not their names, not your browsing, not your keystrokes, not
            your screen. The agent has no field anywhere in its protocol for those. It
            also cannot be sent a command to run: the server can only publish signed
            settings, which is why a compromised server cannot execute code on your
            laptop.
          </p>

          <h3 className="small-head">It needs administrator rights to install</h3>
          <p className="muted">
            Installing creates a system service, which needs your password once. The
            service itself then runs as its own unprivileged account with no special
            permissions — it cannot read your home directory.
          </p>
        </section>

        {/* ----------------------------------------------------------------- */}
        {/* 6. Troubleshooting                                                 */}
        {/* ----------------------------------------------------------------- */}
        <section className="card">
          <h2>If something goes wrong</h2>

          <h3 className="small-head">“That token was refused”</h3>
          <p className="muted">
            Tokens work once and expire. The usual causes are that it was already used,
            that too much time has passed, or that it was copied incompletely. Ask for a
            new one, then finish with:
            <br />
            <code>sudo /opt/ubuntuguard/venv/bin/ubuntuguard-agent enroll --token-prompt</code>
            <br />
            <code>sudo systemctl start ubuntuguard-agent</code>
          </p>

          <h3 className="small-head">“python3-venv is missing”</h3>
          <p className="muted">
            Install it and run the installer again:
            <br />
            <code>sudo apt-get install -y python3-venv</code>
          </p>

          <h3 className="small-head">“This machine is not supported”</h3>
          <p className="muted">
            The installer refuses anything that is not Ubuntu on a 64-bit Intel or ARM
            processor, and it says what it found. Send that line to your administrator.
          </p>

          <h3 className="small-head">Checking it afterwards</h3>
          <p className="muted">
            To see what the agent thinks of itself:
            <br />
            <code>/opt/ubuntuguard/venv/bin/ubuntuguard-agent status</code>
            <br />
            And for the service log:
            <br />
            <code>journalctl -u ubuntuguard-agent -n 50</code>
          </p>

          <h3 className="small-head">Anything else</h3>
          <p className="muted">
            Contact your IT administrator. Include the output of the two commands above —
            it is the quickest way to get an answer, and it contains no secrets.
          </p>
        </section>
      </main>

      <footer className="enroll-foot muted small">
        <p>
          This page is for employees enrolling a company laptop. Administrators sign in at{" "}
          <a href="/">the management console</a>.
        </p>
        <p>
          Your enrollment token is never entered on this page and never sent to a web
          form. It is typed into the installer on your own machine.
        </p>
      </footer>
    </div>
  );
}
