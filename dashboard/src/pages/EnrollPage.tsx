import { useEffect, useState } from "react";

import { api } from "../api/client";
import { copyText } from "../clipboard";
import Brand from "../components/Brand";
import type { DebPackageInfoResponse, InstallerInfoResponse } from "../api/client";

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
 *
 * Two downloads, offered in that order
 * ------------------------------------
 * The `.deb` is offered first because apt resolves usbguard for it and because
 * enrollment afterwards happens in a window.
 *
 * How it is installed took two corrections. The page first said to
 * double-click it, which produces a file that "would not open": the Archive
 * Manager holds the default association for a `.deb`, so double-clicking opens
 * it as an archive. The page was then corrected to say Ubuntu cannot install a
 * downloaded package graphically at all, which is wrong on 22.04 -- it ships
 * gnome-software's dpkg plugin and a "Software Install" handler, reachable
 * through Files -> right-click -> Open With Other Application. It IS true on
 * some releases: 24.04 could not do it when first released, and 26.04 ships no
 * handler. So the graphical route is the instruction and `apt install` is
 * offered as the fallback that always works.
 *
 * The shell installer stays as the alternative. It genuinely does need a
 * terminal, because a browser cannot mark a download executable.
 *
 * The page is careful about one thing in particular: installing the package
 * does NOT enrol the laptop. Enrollment consumes a single-use token and creates
 * an auditable identity, so it needs a person behind it, and a package unpacked
 * by apt has nobody to ask. An employee who installs and then sees
 * nothing happen would reasonably conclude it had failed, so the second step is
 * stated as a step rather than as a footnote.
 *
 * Either download may be absent. The server answers 503 per artifact, and the
 * page offers whatever is actually published rather than linking a 503.
 */

const DOWNLOAD_PATH = "/api/v1/installer/download";
const DEB_DOWNLOAD_PATH = "/api/v1/installer/deb/download";

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} bytes`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function EnrollPage() {
  const [installer, setInstaller] = useState<InstallerInfoResponse | null>(null);
  const [deb, setDeb] = useState<DebPackageInfoResponse | null>(null);
  /** Null while loading, a string once we know NEITHER download is available. */
  const [unavailable, setUnavailable] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      // Fetched together and settled independently. The two artifacts are
      // published separately, so one being absent is a normal deployment state
      // and must not hide the other. `allSettled` rather than `all` for
      // exactly that reason: `all` would reject on the missing one and the
      // page would offer neither.
      const [scriptResult, debResult] = await Promise.allSettled([
        api.installerInfo(),
        api.debInfo(),
      ]);
      if (cancelled) return;

      if (scriptResult.status === "fulfilled") setInstaller(scriptResult.value);
      if (debResult.status === "fulfilled") setDeb(debResult.value);

      // Only an error when there is nothing at all to offer. The server says
      // 503 with a reason; it is shown as prose rather than as a status code,
      // because the employee cannot fix it and the only useful action is to
      // tell somebody.
      if (scriptResult.status === "rejected" && debResult.status === "rejected") {
        const reason = scriptResult.reason;
        setUnavailable(
          reason instanceof Error && reason.message
            ? reason.message
            : "The agent download is not available on this server.",
        );
      }
      setLoading(false);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  function copy(label: string, value: string) {
    // This page is reached by an employee over plain HTTP, where
    // `navigator.clipboard` does not exist, so the old call silently did
    // nothing. `copyText` falls back to execCommand.
    void copyText(value).then((outcome) => {
      if (outcome !== "copied") return;
      setCopied(label);
      window.setTimeout(() => setCopied(null), 2000);
    });
  }

  const runCommand = installer ? `./${installer.filename}` : "./ubuntuguard-agent-installer.sh";

  // The integrity section describes whichever artifact the employee is most
  // likely to have downloaded, which is the one offered first.
  const verifiable = deb ?? installer;
  const verifyCommand = verifiable
    ? `sha256sum ${verifiable.filename}`
    : "sha256sum ubuntuguard-agent-installer.sh";

  return (
    <div className="enroll-shell">
      <header className="enroll-head">
        <Brand size="large" />
        <p className="muted">Device enrollment for company Ubuntu laptops.</p>
      </header>

      <main className="enroll-body">
        {/* ----------------------------------------------------------------- */}
        {/* 1. Download                                                        */}
        {/* ----------------------------------------------------------------- */}
        <section className="card">
          <h2>Install the UbuntuGuard agent</h2>
          <p className="muted">
            Two things are needed: the download below, and a one-time enrollment token
            from your IT administrator. Get the token when you are ready — it works once
            and it expires.
          </p>

          {loading && <p className="muted small">Checking the available downloads…</p>}

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

          {/*
            The package first, because apt resolves usbguard for it and
            because enrollment afterwards is a window rather than a terminal.
            Two corrections live in the wording here, both learned by getting
            them wrong:

            A plain double-click is not the instruction. On Ubuntu 22.04
            gnome-software ships the dpkg plugin and a "Software Install"
            handler, so a local package CAN be installed graphically -- but
            the Archive Manager holds the default association for
            application/vnd.debian.binary-package, so double-clicking opens
            the package as an archive. The route that works is Files ->
            right-click -> Open With Other Application -> Software Install.
            This page first promised a double-click, which produced a file
            that "would not open", and was then corrected too far in the other
            direction by claiming Ubuntu cannot do it at all, which is only
            true on some releases. The terminal command is given as the
            fallback that always works rather than as the main instruction.

            It does not enrol. That is deliberate and is stated separately
            below rather than left for them to discover.
          */}
          {deb && (
            <>
              <a className="download-button" href={DEB_DOWNLOAD_PATH} download>
                Download for Ubuntu ({formatSize(deb.size_bytes)})
              </a>
              <p className="muted small">
                Everything the agent needs is inside this file, so the install needs no
                internet access of its own. Open it from <strong>Files</strong> with{" "}
                <strong>Software Install</strong> — a plain double-click usually opens
                the Archive Manager instead. Entering your token afterwards happens in
                a window.
              </p>

              <dl className="download-facts">
                <div>
                  <dt>Version</dt>
                  <dd className="mono">{deb.deb_version}</dd>
                </div>
                <div>
                  <dt>For</dt>
                  <dd className="mono">
                    Ubuntu {deb.architecture === "amd64" ? "64-bit Intel/AMD" : deb.architecture}
                  </dd>
                </div>
                <div>
                  <dt>Manages this device for</dt>
                  <dd className="mono">{deb.server_url}</dd>
                </div>
              </dl>

              {deb.enrols_on_install === false && (
                <div className="banner warn">
                  <div className="banner-head">
                    <strong>Installing is step one of two</strong>
                  </div>
                  <p>
                    Installing the package puts the agent on this laptop but does not
                    register it. Nothing is reported, and no policy applies, until you
                    open <strong>Enrol this laptop with UbuntuGuard</strong> from your
                    applications menu and paste your token. That second step exists so
                    that registering a laptop is always something a person did, with a
                    token issued to them, rather than something a downloaded file did on
                    its own.
                  </p>
                </div>
              )}
            </>
          )}

          {/* The script, offered as the alternative for anyone in a terminal. */}
          {installer && (
            <details className="alt-download">
              <summary>{deb ? "Prefer the terminal? Download the script installer" : "Download the installer"}</summary>
              <p className="muted small">
                One command installs and enrols in a single pass, which is quicker if you
                already have a terminal open. It needs <code>python3-venv</code> and it
                does not install <code>usbguard</code> for you.
              </p>
              <a className="download-button secondary" href={DOWNLOAD_PATH} download>
                Download the script ({formatSize(installer.size_bytes)})
              </a>
              <dl className="download-facts">
                <div>
                  <dt>Version</dt>
                  <dd className="mono">{installer.agent_version}</dd>
                </div>
                <div>
                  <dt>Manages this device for</dt>
                  <dd className="mono">{installer.server_url}</dd>
                </div>
              </dl>
            </details>
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

          {deb && (
            <>
              <h3 className="small-head">Using the Ubuntu package (recommended)</h3>
              <ol className="steps numbered">
                <li>
                  <strong>Ask your administrator for an enrollment token.</strong> It is a
                  long one-time code. It expires, and it works exactly once, so get it
                  when you are ready to install.
                </li>
                <li>
                  <strong>Download the package</strong> using the button above. It saves
                  to your Downloads folder.
                </li>
                <li>
                  <strong>Install it.</strong> Open <strong>Files</strong> and go to
                  your Downloads folder. Right-click the downloaded package, choose{" "}
                  <strong>Open With Other Application</strong>, then{" "}
                  <strong>Software Install</strong>, and press{" "}
                  <strong>Install</strong>.
                  <br />
                  Enter your own login password when asked — that is Ubuntu asking
                  permission to install a system service, and it is <em>not</em> the
                  enrollment token.
                  <br />
                  <span className="muted small">
                    Open it from Files rather than from your browser's download list.
                    Firefox can keep a download in a private temporary folder that the
                    installer is not allowed to read, which fails with a confusing
                    permissions error.
                  </span>
                  <br />
                  <span className="muted small">
                    A plain double-click usually opens the Archive Manager instead,
                    because that is what Ubuntu associates with these files by default.
                    To change that: right-click the file, Properties, Open With, pick
                    Software Install, Set as default.
                  </span>
                </li>
                <li>
                  <strong>If that does not work</strong>, install it from a terminal
                  instead:
                  <br />
                  <code>sudo apt install ~/Downloads/{deb.filename}</code>
                  <br />
                  <span className="muted small">
                    Some Ubuntu releases cannot install a downloaded package
                    graphically at all — 24.04 could not when it was first released,
                    and 26.04 ships no handler for it. This command always works.
                  </span>
                </li>
                <li>
                  <strong>Open “Enrol this laptop with UbuntuGuard”</strong> from your
                  applications menu — press the Super key and start typing{" "}
                  <code>enrol</code>. This is the step that registers the laptop;
                  installing alone does not.
                </li>
                <li>
                  <strong>Paste the enrollment token</strong> into the box and press OK.
                  Nothing appears as you type or paste; that is deliberate. You will be
                  asked for your password once more, then it is done.
                </li>
              </ol>
              <p className="muted small">
                The agent starts reporting straight away and comes back automatically
                after a reboot. You do not need to keep the download or the token
                afterwards.
              </p>
            </>
          )}

          {installer && (
            <>
              <h3 className="small-head">
                {deb ? "Using the script instead (terminal)" : "Installing the agent"}
              </h3>
              <ol className="steps numbered">
                <li>
                  <strong>Ask your administrator for an enrollment token.</strong>
                </li>
                <li>
                  <strong>Download the script</strong> using the button above.
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
                  You will be asked for your own login password first — that is Ubuntu
                  asking permission to install a system service, and it is not the
                  enrollment token.
                </li>
                <li>
                  <strong>Paste the enrollment token</strong> when it asks. Nothing
                  appears on screen as you type or paste; that is deliberate.
                </li>
              </ol>
              <p className="muted small">
                This route installs and enrols in one pass, so there is no second step.
              </p>
            </>
          )}
        </section>

        {/* ----------------------------------------------------------------- */}
        {/* 4. Optional integrity check                                        */}
        {/* ----------------------------------------------------------------- */}
        {verifiable && (
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
              <code className="token break">{verifiable.sha256}</code>
              <button
                type="button"
                className="ghost"
                onClick={() => copy("sha", verifiable.sha256)}
              >
                {copied === "sha" ? "Copied" : "Copy"}
              </button>
            </div>
            {/*
              Stated precisely, because "verified" is a word that invites more
              trust than this earns. A digest published next to a download
              proves the bytes match what this server holds; it is not a
              signature, and it does not prove who built them.
            */}
            <p className="muted small">
              This compares the file against the digest this server publishes. It is not a
              package signature — Ubuntu will say the package is from an unknown source
              when you install it, which is expected for software your own IT team built.
              {installer && (
                <>
                  {" "}
                  The script installer additionally checks itself: it verifies the agent
                  embedded inside it before unpacking anything.
                </>
              )}
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
