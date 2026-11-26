// End-to-end check of Windows routing with an iptable config that has no single first hop
// (OutlineFoundation/outline-apps#2887). Mirrors what the Electron client does on Windows:
// configureRouting via OutlineService, then tun2socks bound to the returned
// gateway adapter.

import fs from 'node:fs';
import net from 'node:net';
import {spawn, spawnSync} from 'node:child_process';

const TUN2SOCKS = process.argv[2];
const PIPE = '\\\\.\\pipe\\OutlineServicePipe';
const DIRECT_IP = '1.1.1.1'; // In the iptable, dialed directly.
const PROXIED_IP = '1.0.0.1'; // Not in the iptable, goes through the Shadowsocks fallback.

const sleep = ms => new Promise(r => setTimeout(r, ms));
const log = (...a) => console.log(`[e2e ${new Date().toISOString()}]`, ...a);

// --- Access key -------------------------------------------------------------------------------
// With TEST_SS_KEY, the iptable falls back to Shadowsocks, as in #2887. Without it, everything is
// direct: that still exercises OutlineService, the adapter binding and the iptable direct branch,
// but not the proxy.
const m = /^ss:\/\/([^@]+)@([^:/?#]+):(\d+)/.exec(process.env.TEST_SS_KEY ?? '');
const HAS_SS = Boolean(m);
let ss = {$type: 'direct'};
let ssHost = '\0';
if (HAS_SS) {
  let userinfo = decodeURIComponent(m[1]);
  if (!userinfo.includes(':')) userinfo = Buffer.from(userinfo, 'base64').toString();
  const sep = userinfo.indexOf(':');
  ss = {
    $type: 'shadowsocks',
    endpoint: `${m[2]}:${m[3]}`,
    cipher: userinfo.slice(0, sep),
    secret: userinfo.slice(sep + 1),
  };
  // The fork is public: keep the server address and secret out of the logs.
  console.log(`::add-mask::${m[2]}`);
  console.log(`::add-mask::${ss.secret}`);
  ssHost = m[2];
} else {
  console.log('::warning::TEST_SS_KEY not set: running direct-only, the Shadowsocks checks are skipped');
}

const clientConfig = JSON.stringify({
  transport: {
    $type: 'tcpudp',
    tcp: {
      $type: 'iptable',
      table: [{ips: [`${DIRECT_IP}/32`], dialer: {$type: 'direct'}}],
      fallback: ss,
    },
    udp: ss,
  },
});
// Baseline without the iptable, to tell iptable problems apart from runner/DNS problems.
const ssOnlyConfig = JSON.stringify({transport: {$type: 'tcpudp', tcp: ss, udp: ss}});

// --- Helpers ----------------------------------------------------------------------------------
function trace(target, timeoutSec = 10) {
  const r = spawnSync('curl.exe', ['-s', '--max-time', String(timeoutSec), `https://${target}/cdn-cgi/trace`], {
    encoding: 'utf8',
  });
  if (r.status !== 0) return {ok: false, err: `curl exit ${r.status}`};
  const ip = /^ip=(.+)$/m.exec(r.stdout)?.[1]?.trim();
  return ip ? {ok: true, ip} : {ok: false, err: 'no ip= in response'};
}

async function traceWithRetry(target, attempts = 4) {
  let res;
  for (let i = 0; i < attempts; i++) {
    res = trace(target);
    if (res.ok) return res;
    await sleep(2000);
  }
  return res;
}

function checkConnectivity(adapterIndex, cfg = clientConfig) {
  const args = ['-client', cfg, '-checkConnectivity'];
  if (adapterIndex) args.push('-adapterIndex', adapterIndex);
  const r = spawnSync(TUN2SOCKS, args, {encoding: 'utf8', timeout: 60000});
  const line = (r.stdout ?? '').split('\n')[0];
  try {
    return {exit: r.status, ...JSON.parse(line)};
  } catch {
    return {exit: r.status, raw: line, stderr: r.stderr};
  }
}

function bestDefaultRouteIfIndex() {
  const r = spawnSync(
    'powershell.exe',
    [
      '-NoProfile',
      '-Command',
      "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0 | Where-Object { (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex).Name -ne 'outline-tap0' } | Sort-Object { $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4).InterfaceMetric } | Select-Object -First 1 -ExpandProperty InterfaceIndex",
    ],
    {encoding: 'utf8'}
  );
  return r.stdout.trim();
}

function dnsDiagnostics(label) {
  const run = (cmd, args) => {
    const r = spawnSync(cmd, args, {encoding: 'utf8', timeout: 20000});
    log(`[dns ${label}] ${cmd} ${args.join(' ')} -> exit ${r.status}\n${(r.stdout ?? '') + (r.stderr ?? '')}`);
  };
  run('powershell.exe', ['-NoProfile', '-Command', 'Get-DnsClientServerAddress -AddressFamily IPv4 | Format-Table -AutoSize | Out-String -Width 200']);
  run('powershell.exe', ['-NoProfile', '-Command', "Get-NetAdapter | Format-Table Name, ifIndex, Status, MediaConnectionState -AutoSize | Out-String -Width 200; Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -in '0.0.0.0/0','0.0.0.0/1','128.0.0.0/1','169.254.113.53/32' } | Format-Table DestinationPrefix, NextHop, ifIndex, RouteMetric, State, Store -AutoSize | Out-String -Width 200; Find-NetRoute -RemoteIPAddress 1.0.0.1 | Select-Object -Last 1 | Format-List DestinationPrefix, InterfaceIndex, NextHop | Out-String"]);
  run('powershell.exe', ['-NoProfile', '-Command', 'Clear-DnsClientCache; Resolve-DnsName www.cloudflare.com -Type A -DnsOnly | Format-Table -AutoSize | Out-String -Width 200']);
  run('nslookup.exe', ['www.cloudflare.com', '169.254.113.53']);
  run('nslookup.exe', ['-vc', 'www.cloudflare.com', '169.254.113.53']);
}

function connectService() {
  return new Promise((resolve, reject) => {
    const sock = net.createConnection(PIPE);
    const waiters = [];
    sock.on('data', d => {
      for (const part of d.toString().split(/(?<=\})\s*(?=\{)/)) {
        const msg = JSON.parse(part);
        if (msg.action === 'statusChanged') {
          log('service statusChanged:', JSON.stringify(msg));
        } else {
          waiters.shift()?.(msg);
        }
      }
    });
    sock.on('error', reject);
    sock.on('connect', () =>
      resolve({
        request(req) {
          return new Promise((res, rej) => {
            const timer = setTimeout(() => rej(new Error(`no response to ${req.action}`)), 60000);
            waiters.push(msg => {
              clearTimeout(timer);
              res(msg);
            });
            sock.write(JSON.stringify(req));
          });
        },
        close: () => sock.destroy(),
      })
    );
  });
}

function startTun2socks(adapterIndex, cfg = clientConfig) {
  const args = [];
  if (adapterIndex) args.push('-adapterIndex', adapterIndex);
  args.push(
    '-keyID', 'e2e',
    '-tunName', 'outline-tap0',
    '-tunAddr', '10.0.85.2',
    '-tunGw', '10.0.85.1',
    '-tunMask', '255.255.255.0',
    '-tunDNS', '1.1.1.1,9.9.9.9',
    '-client', cfg,
    '-logLevel', 'info'
  );
  const p = spawn(TUN2SOCKS, args, {stdio: ['ignore', 'pipe', 'pipe']});
  p.stdout.on('data', d => process.stdout.write(`[tun2socks] ${d}`));
  p.stderr.on('data', d => process.stdout.write(`[tun2socks] ${d}`));
  p.on('exit', code => log(`tun2socks exited with ${code}`));
  return p;
}

async function stopTun2socks(p) {
  if (p && p.exitCode === null) {
    p.kill();
    await new Promise(r => p.once('exit', r));
  }
}

// --- Test -------------------------------------------------------------------------------------
const results = [];
function check(name, pass, detail, required = true) {
  detail = String(detail).split(ssHost).join('***');
  if (ss.secret) detail = detail.split(ss.secret).join('***');
  results.push({name, pass, detail, required});
  log(`${pass ? 'PASS' : required ? 'FAIL' : 'INFO'}: ${name} — ${detail}`);
}

let service;
let tun2socks;
try {
  const baseline = trace(DIRECT_IP);
  if (!baseline.ok) throw new Error(`baseline curl failed: ${baseline.err}`);
  const runnerIp = baseline.ip;
  log(`runner public IP: ${runnerIp}`);

  // Electron runs this before routing is configured, without an adapter index.
  const cc0 = checkConnectivity();
  check('checkConnectivity before routing', cc0.exit === 0 && !cc0.tcp, JSON.stringify(cc0));

  const expectedIf = bestDefaultRouteIfIndex();
  service = await connectService();
  const routedAt = new Date();
  const conf = await service.request({
    action: 'configureRouting',
    parameters: {isAutoConnect: false},
  });
  check('configureRouting without proxyIp', conf.statusCode === 0, JSON.stringify(conf));
  const gw = conf.gatewayAdapterIndex;
  check(
    'gatewayAdapterIndex is the best non-TAP default route',
    gw === expectedIf,
    `service=${gw} Get-NetRoute=${expectedIf}`,
    false
  );

  const captured = trace(DIRECT_IP, 5);
  // Informational: with no process attached the TAP is media-disconnected, so Windows may ignore
  // its routes until tun2socks opens it.
  check('routing active, no tun2socks yet: is traffic captured by the TAP?', !captured.ok, JSON.stringify(captured), false);

  const cc1 = checkConnectivity(gw);
  check('checkConnectivity with -adapterIndex while routed', cc1.exit === 0 && !cc1.tcp, JSON.stringify(cc1));

  // Baseline without the iptable. It also warms up the TAP: on a fresh runner the first session
  // doesn't get the TAP's DNS servers in time.
  tun2socks = startTun2socks(gw, ssOnlyConfig);
  await sleep(5000);
  dnsDiagnostics('baseline');
  const baseProxied = await traceWithRetry(PROXIED_IP);
  check(
    `baseline (no iptable): ${PROXIED_IP} exits through ${HAS_SS ? 'Shadowsocks' : 'the direct dialer'}`,
    baseProxied.ok && (HAS_SS ? baseProxied.ip !== runnerIp : baseProxied.ip === runnerIp),
    baseProxied.ok ? `egress != runner IP: ${baseProxied.ip !== runnerIp}` : baseProxied.err,
    false
  );
  const baseName = await traceWithRetry('www.cloudflare.com');
  check(
    'baseline (no iptable): hostname works',
    baseName.ok && (HAS_SS ? baseName.ip !== runnerIp : true),
    baseName.ok ? `egress != runner IP: ${baseName.ip !== runnerIp}` : baseName.err,
    false
  );
  await stopTun2socks(tun2socks);

  tun2socks = startTun2socks(gw);
  await sleep(5000);
  dnsDiagnostics('iptable');

  const direct = await traceWithRetry(DIRECT_IP);
  check(
    `iptable direct branch (${DIRECT_IP}) exits from the runner IP`,
    direct.ok && direct.ip === runnerIp,
    direct.ok ? `egress ${direct.ip === runnerIp ? '== runner IP' : '!= runner IP'}` : direct.err
  );

  const proxied = await traceWithRetry(PROXIED_IP);
  check(
    HAS_SS ? `iptable fallback (${PROXIED_IP}) exits through Shadowsocks` : `iptable fallback (${PROXIED_IP}) works (direct, no SS key)`,
    proxied.ok && (HAS_SS ? proxied.ip !== runnerIp : proxied.ip === runnerIp),
    proxied.ok ? `egress != runner IP: ${proxied.ip !== runnerIp}, egress == SS host: ${proxied.ip === ssHost}` : proxied.err
  );

  const byName = await traceWithRetry('www.cloudflare.com');
  check(
    'iptable: hostname (system DNS through the tunnel) works',
    byName.ok && (HAS_SS ? byName.ip !== runnerIp : true),
    byName.ok ? `egress != runner IP: ${byName.ip !== runnerIp}` : byName.err,
    // Without SS, DNS goes out over direct UDP, which smartdnsblock drops (see below).
    HAS_SS
  );

  const dns = spawnSync('nslookup.exe', ['example.com', '8.8.8.8'], {encoding: 'utf8', timeout: 20000});
  check(
    'iptable: UDP DNS query to 8.8.8.8 through the tunnel',
    dns.status === 0 && /Name:\s+example\.com/.test(dns.stdout ?? ''),
    (dns.stdout ?? '').replace(/\s+/g, ' ').trim(),
    // Without SS, UDP is direct and smartdnsblock drops port 53 outside the TAP by design.
    HAS_SS
  );

  // Starting tun2socks fires NetworkAddressChanged. While routing is configured the service must
  // treat itself as connected, which used to be keyed on proxyIp != null.
  const ev = spawnSync('powershell.exe', ['-NoProfile', '-Command',
    `Get-EventLog -LogName Application -Source OutlineService -After ([datetime]::Parse('${routedAt.toISOString()}')) | Where-Object { $_.Message -like 'network changed*' } | ForEach-Object { $_.Message }`],
    {encoding: 'utf8'});
  const evLines = (ev.stdout ?? '').split(/\r?\n/).filter(Boolean);
  check(
    'NetworkAddressChanged sees the service as connected',
    evLines.length > 0 && !evLines.some(l => l.includes('not connected')),
    `${evLines.length} events; "not connected": ${evLines.filter(l => l.includes('not connected')).length}`
  );

  // Control: without -adapterIndex the direct dialer isn't bound to the gateway adapter, so its
  // packets go back into the TAP. This shows the binding, not a proxy route, is what makes the
  // direct branch work.
  await stopTun2socks(tun2socks);
  tun2socks = startTun2socks(undefined);
  await sleep(3000);
  const unbound = trace(DIRECT_IP, 8);
  check(
    'control: without -adapterIndex the direct branch does NOT reach the internet',
    !unbound.ok || unbound.ip !== runnerIp,
    JSON.stringify(unbound.ok ? {ok: true, egressIsRunner: unbound.ip === runnerIp} : unbound),
    false
  );
} catch (e) {
  check('unexpected error', false, e.stack ?? String(e));
} finally {
  await stopTun2socks(tun2socks);
  if (service) {
    const reset = await service
      .request({action: 'resetRouting', parameters: {}})
      .catch(e => ({error: e.message}));
    log('resetRouting:', JSON.stringify(reset));
    service.close();
  }
  const after = trace(DIRECT_IP);
  check('connectivity restored after resetRouting', after.ok, JSON.stringify(after.ok ? {ok: true} : after), false);
}

const summary = [
  '| Result | Check | Detail |',
  '| --- | --- | --- |',
  ...results.map(
    r => `| ${r.pass ? '✅' : r.required ? '❌' : 'ℹ️'} | ${r.name} | ${String(r.detail).replace(/\|/g, '\\|').slice(0, 300)} |`
  ),
].join('\n');
console.log('\n' + summary);
if (process.env.GITHUB_STEP_SUMMARY) fs.appendFileSync(process.env.GITHUB_STEP_SUMMARY, summary + '\n');
process.exit(results.some(r => r.required && !r.pass) ? 1 : 0);
