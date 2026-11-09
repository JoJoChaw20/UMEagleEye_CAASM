// The Agents page's Install tab: what to download for each kind of computer, how to install it, and
// how to connect it (a connection code for one computer, an install code for many).
// The downloads are served by the API from R2 (GET /agents/installer, /installer/download?package=):
// always the newest upload of each, so the buttons name no version (it is shown beside them).
// They carry no secrets: the connection code does.
import { useEffect, useState } from 'react'
import { Apple, Download, Monitor, Plus, Server, Smartphone, Terminal } from 'lucide-react'
import client from '../../api/client'
import InstallCodesCard from './InstallCodesCard'
import { CopyButton } from './parts'

// {windows, source}: each {filename, version, size, uploaded_at} or null; undefined while loading,
// null when nothing is uploaded or the request failed.
export function useDownloads() {
  const [downloads, setDownloads] = useState(undefined)
  useEffect(() => {
    let live = true
    client.get('/agents/installer')
      .then((r) => live && setDownloads(r.data.packages ?? { windows: r.data, source: null }))   // a server before the source package
      .catch(() => live && setDownloads(null))
    return () => { live = false }
  }, [])
  return downloads
}

const formatMB = (bytes) => `${Math.max(1, Math.round(bytes / 2 ** 20))} MB`
const formatDay = (iso) => (iso ? new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : '')

// One download: `pkg` is the package's details (null: not uploaded yet), `package` its name in the API.
export function DownloadButton({ pkg, package: kind = 'windows', label, className = 'btn-secondary', details = true }) {
  const [state, setState] = useState(null)                   // null | 'downloading' | error text
  if (pkg === undefined) return null
  if (pkg === null) {
    return <span className="text-xs text-dark-400" title="Ask the platform administrator to upload it">Not available yet</span>
  }
  const download = async () => {
    setState('downloading')
    try {
      const res = await client.get('/agents/installer/download', { params: { package: kind }, responseType: 'blob', timeout: 0 })
      const url = URL.createObjectURL(res.data)
      const a = document.createElement('a')
      a.href = url
      a.download = pkg.filename
      document.body.appendChild(a)
      a.click()
      a.remove()
      setTimeout(() => URL.revokeObjectURL(url), 10_000)
      setState(null)
    } catch {
      setState('Download failed. Try again.')
    }
  }
  return (
    <span className="inline-flex items-center gap-3 flex-wrap">
      <button type="button" onClick={download} disabled={state === 'downloading'} title={pkg.filename}
        className={`${className} inline-flex items-center gap-2 text-sm`}>
        <Download className={`w-4 h-4 ${state === 'downloading' ? 'animate-pulse' : ''}`} />
        {state === 'downloading' ? 'Downloading...' : label}
      </button>
      {details && (
        <span className="text-xs text-dark-400">
          Version {pkg.version} · {formatMB(pkg.size)}{pkg.uploaded_at ? ` · published ${formatDay(pkg.uploaded_at)}` : ''}
        </span>
      )}
      {state && state !== 'downloading' && <span className="text-xs text-red-400">{state}</span>}
    </span>
  )
}

function Commands({ children }) {
  const text = children.trim()
  return (
    <div className="relative group">
      <pre className="bg-dark-950/80 border border-dark-700/60 rounded-lg p-3 pr-10 text-xs font-mono text-dark-100 overflow-x-auto whitespace-pre">{text}</pre>
      <div className="absolute top-1.5 right-1.5"><CopyButton text={text} label="Copy the commands" /></div>
    </div>
  )
}

function Step({ n, title, children }) {
  return (
    <li className="flex gap-3">
      <span className="flex-shrink-0 w-6 h-6 rounded-full bg-eagle-500/15 border border-eagle-500/30 text-eagle-300 text-xs flex items-center justify-center mt-0.5">{n}</span>
      <div className="min-w-0 flex-1 space-y-2">
        <p className="text-sm text-dark-50 font-medium">{title}</p>
        <div className="text-sm text-dark-300 space-y-2">{children}</div>
      </div>
    </li>
  )
}

function Requirements({ items }) {
  return (
    <ul className="text-xs text-dark-400 space-y-0.5">
      {items.map((t) => <li key={t}>• {t}</li>)}
    </ul>
  )
}

function WindowsGuide({ pkg }) {
  const file = pkg?.filename ?? 'EagleEyeAgent-Setup-<version>.exe'
  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <DownloadButton pkg={pkg} package="windows" label="Download for Windows" className="btn-primary" />
      </div>
      <Requirements items={['Windows 10 or 11, or Windows Server (64-bit)', 'Administrator rights to install', 'HTTPS out to this EagleEye server']} />
      <ol className="space-y-4">
        <Step n={1} title="Get a code for it">
          <p>One computer: <strong>Register agent</strong> below gives its connection code. Many computers: make an <strong>install code</strong> below.</p>
        </Step>
        <Step n={2} title="Install">
          <p>Run <code className="font-mono text-xs">{file}</code>. It installs the agent as a Windows service that starts with the computer.</p>
        </Step>
        <Step n={3} title="Connect">
          <p>Open <strong>EagleEye Agent</strong>, go to <strong>Connection</strong>, paste the code, choose <strong>Use code</strong>, then <strong>Test connection</strong> and <strong>Save</strong>. The agent shows as Online on the Agents tab within a minute.</p>
        </Step>
        <Step n={4} title="Many computers: Intune, Group Policy or a script">
          <p>Silent, and connected at once with an install code (each computer registers as an agent of its own):</p>
          <Commands>{`${file} /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /MERGETASKS="!autostart" /CONNECTIONCODEFILE=\\\\server\\share\\eagleeye-code.txt`}</Commands>
          <p className="text-xs text-dark-400">
            Exit code 0: installed and connected. 10: installed but not connected (an expired or used-up code, or no connection to the server).
            Intune detection rule: the file <code className="font-mono">%ProgramFiles%\EagleEye Agent\eagleeye.exe</code>.
            Keeping the code in a file keeps it off the command line; <code className="font-mono">/CONNECTIONCODE=EE2…</code> also works.
          </p>
        </Step>
      </ol>
      <p className="text-xs text-dark-400">Updating: run the newer installer over the old one; the agent keeps its connection and settings.</p>
    </div>
  )
}

function LinuxGuide({ pkg }) {
  const dir = pkg ? pkg.filename.replace(/\.tar\.gz$/, '') : 'eagleeye-agent-<version>'
  return (
    <div className="space-y-5">
      <DownloadButton pkg={pkg} package="source" label="Download for Linux (.tar.gz)" className="btn-primary" />
      <Requirements items={['A Linux server with systemd (Ubuntu, Debian, RHEL and others)', 'Python 3.12 or later, and root (sudo)', 'HTTPS out to this EagleEye server']} />
      <ol className="space-y-4">
        <Step n={1} title="Get a code for it">
          <p><strong>Register agent</strong> below (one server) or an <strong>install code</strong> (many servers).</p>
        </Step>
        <Step n={2} title="Install and connect">
          <Commands>{`sudo tar xzf ${pkg?.filename ?? `${dir}.tar.gz`} -C /opt && cd /opt/${dir}
sudo python3 -m venv .venv && sudo .venv/bin/pip install .
sudo .venv/bin/python -m eagleeye service enrol --connection-code 'EE…'
sudo .venv/bin/python -m eagleeye service install
sudo .venv/bin/python -m eagleeye service status`}</Commands>
          <p className="text-xs text-dark-400">
            It runs as the systemd service <code className="font-mono">eagleeye-agent</code>; its settings and logs are in <code className="font-mono">/var/lib/eagleeye</code>
            (log: <code className="font-mono">journalctl -u eagleeye-agent</code>). For many servers, <code className="font-mono">--connection-code-file</code> keeps the code off the command line.
          </p>
        </Step>
        <Step n={3} title="Optional: SBOM tools">
          <p>For the SBOM and its CVEs, install Syft and Grype (Grype's database needs about 6 GB free):</p>
          <Commands>{`curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin`}</Commands>
        </Step>
      </ol>
      <p className="text-xs text-dark-400">Updating: unpack the new version and run <code className="font-mono">service install</code> from its folder; the connection and settings in /var/lib/eagleeye are kept.</p>
    </div>
  )
}

function NetworkGuide({ pkg }) {
  const dir = pkg ? pkg.filename.replace(/\.tar\.gz$/, '') : 'eagleeye-agent-<version>'
  return (
    <div className="space-y-5">
      <DownloadButton pkg={pkg} package="source" label="Download the network agent (.tar.gz)" className="btn-primary" />
      <p className="text-sm text-dark-300">
        Reads the routers and switches over SNMP (ARP and MAC tables, CDP/LLDP neighbours) to find every device and the switch port it is on.
        Run one per site, on a Linux host next to the network equipment.
      </p>
      <Requirements items={['Linux with Docker (or Python 3.12+ and systemd)', 'UDP 161 to the routers and switches', 'HTTPS out to this EagleEye server; nothing connects to it']} />
      <ol className="space-y-4">
        <Step n={1} title="On the routers and switches (once, by the network team)">
          <p>A read-only SNMPv3 user (SHA with AES-128), allowed only from the agent's address. Cisco IOS:</p>
          <Commands>{`ip access-list standard EAGLEEYE-SNMP
 permit host <agent address>
snmp-server view EAGLEEYE-RO iso included
snmp-server group EAGLEEYE-RO v3 priv read EAGLEEYE-RO access EAGLEEYE-SNMP
snmp-server user eagleeye EAGLEEYE-RO v3 auth sha <auth password> priv aes 128 <priv password>`}</Commands>
        </Step>
        <Step n={2} title="Get a code for it">
          <p><strong>Register agent</strong> below, and save the code in a file named <code className="font-mono text-xs">connection_code</code>.</p>
        </Step>
        <Step n={3} title="Run it in Docker">
          <p>The connection code and SNMP passwords go in files (<code className="font-mono text-xs">connection_code</code>, <code className="font-mono text-xs">snmp_auth</code>, <code className="font-mono text-xs">snmp_priv</code>), never in the environment:</p>
          <Commands>{`tar xzf ${pkg?.filename ?? `${dir}.tar.gz`} && cd ${dir}
docker build -f packaging/network-agent/Dockerfile -t eagleeye-network-agent .
sudo install -d -m 700 -o 10001 /etc/eagleeye/secrets     # put the three files here
sudo chown 10001 /etc/eagleeye/secrets/* && sudo chmod 600 /etc/eagleeye/secrets/*
docker run -d --name eagleeye-network-agent --restart unless-stopped \\
  -e EAGLEEYE_CONNECTION_CODE_FILE=/run/secrets/connection_code -e EAGLEEYE_SNMP_USER=eagleeye \\
  -e EAGLEEYE_SNMP_AUTH_KEY_FILE=/run/secrets/snmp_auth -e EAGLEEYE_SNMP_PRIV_KEY_FILE=/run/secrets/snmp_priv \\
  -v /etc/eagleeye/secrets:/run/secrets:ro -v eagleeye-netagent:/data eagleeye-network-agent`}</Commands>
          <p className="text-xs text-dark-400">Without Docker: the agent README ("Network agent") has the systemd steps.</p>
        </Step>
        <Step n={4} title="Tell it where to start">
          <p>On the Agents tab, open the new network agent and set <strong>Start from</strong> (the core routers or switches) and <strong>Allowed ranges</strong>. It reads the network every 15 minutes; <strong>Run now</strong> reads it at once.</p>
        </Step>
      </ol>
    </div>
  )
}

function MacGuide({ pkg }) {
  const file = pkg?.filename ?? 'eagleeye-agent-<version>.tar.gz'
  const dir = file.replace(/\.tar\.gz$/, '')
  return (
    <div className="space-y-5">
      <DownloadButton pkg={pkg} package="source" label="Download for macOS (.tar.gz)" className="btn-primary" />
      <Requirements items={['macOS 12 or later (Apple silicon or Intel), and an administrator account', "Python 3.12 or later: python.org, or brew install python@3.12 (macOS's own python3 is too old)", 'HTTPS out to this EagleEye server']} />
      <ol className="space-y-4">
        <Step n={1} title="Get a code for it">
          <p><strong>Register agent</strong> below, and save the code in a file, for example <code className="font-mono text-xs">~/code.txt</code>.</p>
        </Step>
        <Step n={2} title="Install and connect (Terminal)">
          <Commands>{`cd ~/Downloads && tar xzf ${file}
sudo bash ${dir}/packaging/macos/install-macos.sh ${file} --code-file ~/code.txt
eagleeye gui`}</Commands>
          <p className="text-xs text-dark-400">
            It runs as the launchd daemon <code className="font-mono">com.umeagleeye.agent</code> (as root, from <code className="font-mono">/usr/local/eagleeye</code>);
            its settings and logs are in <code className="font-mono">/Library/Application Support/EagleEye</code>. It reports the Mac's hardware, macOS version and updates,
            FileVault, the firewall, XProtect, apps and Homebrew packages. Secure Boot and the Secure Enclave cannot be read from a program, so they are shown as unknown.
          </p>
        </Step>
        <Step n={3} title="Optional: SBOM tools and Nmap">
          <Commands>{`brew install syft grype nmap`}</Commands>
        </Step>
      </ol>
      <p className="text-xs text-dark-400">
        Updating: run the same script with the new package (the connection and settings are kept).
        Removing: <code className="font-mono">sudo bash install-macos.sh --uninstall --purge</code>.
      </p>
    </div>
  )
}

function AndroidGuide({ pkg }) {
  return (
    <div className="space-y-5">
      <DownloadButton pkg={pkg} package="android" label="Download for Android (.apk)" className="btn-primary" />
      <Requirements items={['Android 8 or later (phones and tablets)', 'Wi-Fi of your organisation for the first report (on mobile data it waits)', 'HTTPS out to this EagleEye server']} />
      <ol className="space-y-4">
        <Step n={1} title="Get a code for it">
          <p><strong>Register agent</strong> below (one phone), or an <strong>install code</strong> for phones (Install codes, "Phones (Android)") to hand out to many.</p>
        </Step>
        <Step n={2} title="Install the app">
          <p>Open the .apk on the phone and allow installing it (Android asks once for the browser or file app it came from). It is not on Google Play yet.</p>
        </Step>
        <Step n={3} title="Connect">
          <p>Open <strong>EagleEye Agent</strong>, paste the code, and press <strong>Connect</strong>. It reports at once, then checks in every 15 minutes.</p>
        </Step>
      </ol>
      <p className="text-xs text-dark-400">
        It sends the phone's name and model, Android version and security patch level, screen lock, storage encryption,
        signs of root and USB debugging, and its address on the Wi-Fi. Installed apps only when <strong>Include software users installed for themselves</strong> is
        on for it. Never accounts, messages, contacts, photos, files or location; it does not scan or listen to the network.
      </p>
    </div>
  )
}

const PLATFORMS = [
  { key: 'windows', label: 'Windows', icon: Monitor },
  { key: 'linux', label: 'Linux', icon: Terminal },
  { key: 'network', label: 'Network agent', icon: Server },
  { key: 'macos', label: 'macOS', icon: Apple },
  { key: 'android', label: 'Android', icon: Smartphone },
]

export default function InstallTab({ downloads, canManage, isSuperadmin, onRegister }) {
  const [platform, setPlatform] = useState('windows')
  return (
    <div className="space-y-6">
      <div className="glass-card p-6 space-y-5">
        <div>
          <h2 className="font-semibold text-dark-50 text-base">Install the agent</h2>
          <p className="text-xs text-dark-400 mt-0.5">The downloads are always the latest version. Everything an agent does is then set on this dashboard.</p>
        </div>
        <div className="flex flex-wrap gap-2" role="tablist" aria-label="Operating system">
          {PLATFORMS.map(({ key, label, icon: Icon }) => (
            <button key={key} type="button" role="tab" aria-selected={platform === key} onClick={() => setPlatform(key)}
              className={`px-3 py-1.5 rounded-lg text-sm border inline-flex items-center gap-2 transition-colors ${platform === key
                ? 'border-eagle-500/50 bg-eagle-500/15 text-dark-50' : 'border-dark-600/60 text-dark-400 hover:text-dark-200'}`}>
              <Icon className="w-4 h-4" /> {label}
            </button>
          ))}
        </div>
        {platform === 'windows' && <WindowsGuide pkg={downloads === null ? null : downloads?.windows} />}
        {platform === 'linux' && <LinuxGuide pkg={downloads === null ? null : downloads?.source} />}
        {platform === 'network' && <NetworkGuide pkg={downloads === null ? null : downloads?.source} />}
        {platform === 'macos' && <MacGuide pkg={downloads === null ? null : downloads?.source} />}
        {platform === 'android' && <AndroidGuide pkg={downloads === null ? null : downloads?.android ?? null} />}
      </div>

      <div className="glass-card p-6 space-y-3">
        <h2 className="font-semibold text-dark-50 text-base">One computer: a connection code</h2>
        <p className="text-xs text-dark-400 max-w-3xl">
          Register an agent for the computer and paste its connection code into the agent. A connection code belongs to that one agent:
          for many computers use an install code.
        </p>
        {canManage
          ? <button onClick={onRegister} className="btn-primary flex items-center gap-2 text-sm"><Plus className="w-4 h-4" /> Register agent</button>
          : <p className="text-xs text-dark-500">Only a tenant superadmin or admin can register agents.</p>}
      </div>

      {/* Install codes are per tenant: for the tenant's own admins (the platform superadmin has none) */}
      <InstallCodesCard enabled={canManage && !isSuperadmin} />
    </div>
  )
}
