"""End-to-end proxy validation through Xray-core.

The probe rejects loopback/private/reserved endpoints, starts a short-lived local
Xray instance for each candidate, and verifies an external HTTPS request through
that proxy. This is deliberately a bounded validator, not a generic port scanner.
"""
import asyncio, base64, json, os, random, socket, subprocess, tempfile, time, uuid
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
import ipaddress

from .validator import endpoint_info, vmess_obj
from .config import X_RAY_BIN, XRAY_CONCURRENCY, XRAY_TIMEOUT, XRAY_TEST_URL


def _public_host(host):
    try:
        ip = ipaddress.ip_address(host)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified)
    except ValueError:
        # DNS names are allowed; Xray/curl will resolve them. Obvious local names are not.
        h = host.lower().rstrip('.')
        return h not in {'localhost', 'localhost.localdomain'} and not h.endswith(('.local', '.internal', '.lan'))


def _common_stream(q, network, security, host, sni, path):
    ss = {'network': network or 'tcp'}
    if security in {'tls', 'reality'}:
        ss['security'] = security
        if security == 'tls':
            ss['tlsSettings'] = {
                'serverName': sni or host,
                'allowInsecure': True,
            }
            alpn = q.get('alpn', [''])[0]
            if alpn: ss['tlsSettings']['alpn'] = [x for x in alpn.split(',') if x]
        else:
            pub = q.get('pbk', [''])[0] or q.get('publicKey', [''])[0]
            sid = q.get('sid', [''])[0] or q.get('shortId', [''])[0]
            fp = q.get('fp', ['chrome'])[0]
            if not pub: return None
            ss['realitySettings'] = {
                'serverName': sni or host,
                'fingerprint': fp,
                'publicKey': pub,
                'shortId': sid,
            }
    if network in {'ws', 'websocket'}:
        ws = {'path': path or '/'}
        h = q.get('host', [''])[0]
        if h: ws['headers'] = {'Host': h}
        ss['wsSettings'] = ws
    elif network == 'grpc':
        service = q.get('serviceName', [''])[0] or q.get('service_name', [''])[0]
        ss['grpcSettings'] = {'serviceName': service, 'multiMode': False}
    elif network in {'httpupgrade', 'http-upgrade'}:
        ss['network'] = 'httpupgrade'
        hu = {'path': path or '/'}
        h = q.get('host', [''])[0]
        if h: hu['host'] = [h]
        ss['httpupgradeSettings'] = hu
    return ss


def build_outbound(cfg, tag='proxy'):
    proto = cfg.split('://', 1)[0].lower()
    if proto == 'vmess':
        o = vmess_obj(cfg)
        host = str(o.get('add', ''))
        if not host or not _public_host(host): return None
        try: port = int(o.get('port', 443))
        except Exception: return None
        net = str(o.get('net') or 'tcp').lower()
        security = str(o.get('tls') or '').lower()
        if security in {'true', '1'}: security = 'tls'
        q = {}
        sni = str(o.get('sni') or o.get('host') or host)
        if o.get('host'): q['host'] = [str(o['host'])]
        path = str(o.get('path') or '/')
        ss = _common_stream(q, net, security, host, sni, path)
        if ss is None: return None
        user = {'id': str(o.get('id', '')), 'alterId': int(o.get('aid', 0) or 0), 'security': str(o.get('scy', 'auto') or 'auto')}
        if not user['id']: return None
        return {'tag': tag, 'protocol': 'vmess', 'settings': {'vnext': [{'address': host, 'port': port, 'users': [user]}]}, 'streamSettings': ss}
    try:
        u = urlparse(cfg); q = parse_qs(u.query, keep_blank_values=True)
        host = u.hostname or ''
        if not host or not _public_host(host): return None
        port = u.port or 443
        net = q.get('type', q.get('network', ['tcp']))[0].lower()
        security = q.get('security', q.get('tls', ['']))[0].lower()
        sni = q.get('sni', [''])[0] or q.get('host', [''])[0] or host
        path = unquote(q.get('path', ['/'])[0] or '/')
        if proto == 'vless':
            uid = unquote(u.username or '')
            if not uid: return None
            user = {'id': uid, 'encryption': q.get('encryption', ['none'])[0] or 'none'}
            flow = q.get('flow', [''])[0]
            if flow: user['flow'] = flow
            ss = _common_stream(q, net, security, host, sni, path)
            if ss is None: return None
            return {'tag': tag, 'protocol': 'vless', 'settings': {'vnext': [{'address': host, 'port': port, 'users': [user]}]}, 'streamSettings': ss}
        if proto == 'trojan':
            password = unquote(u.username or '')
            if not password: return None
            ss = _common_stream(q, net, 'tls' if security in {'', 'tls', 'https'} else security, host, sni, path)
            if ss is None: return None
            return {'tag': tag, 'protocol': 'trojan', 'settings': {'servers': [{'address': host, 'port': port, 'password': password}]}, 'streamSettings': ss}
        if proto == 'ss':
            # Basic SIP002/Shadowsocks URI support.
            user = unquote(u.username or '')
            if ':' not in user: return None
            method, password = user.split(':', 1)
            return {'tag': tag, 'protocol': 'shadowsocks', 'settings': {'servers': [{'address': host, 'port': port, 'method': method, 'password': password}]}}
    except Exception:
        return None
    return None


def _free_port():
    s = socket.socket(); s.bind(('127.0.0.1', 0)); p = s.getsockname()[1]; s.close(); return p


def _write_config(outbound, socks_port, path):
    cfg = {
        'log': {'loglevel': 'error'},
        'inbounds': [{'tag': 'socks', 'listen': '127.0.0.1', 'port': socks_port,
                      'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': False}}],
        'outbounds': [outbound, {'tag': 'direct', 'protocol': 'freedom'}, {'tag': 'block', 'protocol': 'blackhole'}],
        'routing': {'domainStrategy': 'AsIs', 'rules': [{'type': 'field', 'inboundTag': ['socks'], 'outboundTag': [outbound['tag']]}]}
    }
    Path(path).write_text(json.dumps(cfg, ensure_ascii=False), encoding='utf-8')


async def _probe_one(item, sem):
    async with sem:
        cfg = item.get('config', '')
        outbound = build_outbound(cfg)
        if outbound is None:
            item['xray_ok'] = False; item['xray_error'] = 'unsupported_or_unsafe_config'; return item
        port = _free_port()
        with tempfile.TemporaryDirectory(prefix='xfinder-xray-') as td:
            conf = os.path.join(td, 'config.json')
            _write_config(outbound, port, conf)
            try:
                proc = await asyncio.create_subprocess_exec(
                    X_RAY_BIN, 'run', '-c', conf,
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE
                )
            except Exception as e:
                item['xray_ok'] = False; item['xray_error'] = f'xray_start:{type(e).__name__}'; return item
            try:
                # Give Xray a short startup window and ensure it did not exit immediately.
                await asyncio.sleep(0.25)
                if proc.returncode is not None:
                    err = (await proc.stderr.read()).decode('utf-8', 'ignore')[-300:]
                    item['xray_ok'] = False; item['xray_error'] = 'xray_exit:' + err; return item
                cmd = ['curl', '--silent', '--show-error', '--location', '--max-time', str(int(XRAY_TIMEOUT)),
                       '--socks5-hostname', f'127.0.0.1:{port}', '-o', '/dev/null', '-w', '%{http_code}', XRAY_TEST_URL]
                start = time.perf_counter()
                try:
                    p = await asyncio.wait_for(asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL), timeout=XRAY_TIMEOUT + 2)
                    stdout, _ = await p.communicate()
                    code = stdout.decode().strip()
                    ok = p.returncode == 0 and code.isdigit() and 100 <= int(code) < 500
                except Exception:
                    ok = False; code = ''
                item['xray_ok'] = ok
                item['xray_http_status'] = int(code) if code.isdigit() else None
                item['xray_ping_ms'] = round((time.perf_counter()-start)*1000, 1)
                item['xray_error'] = None if ok else 'proxy_request_failed'
                if ok:
                    item['test_level'] = 'xray'
                    item['alive'] = True
                else:
                    item['alive'] = False
                return item
            finally:
                try:
                    proc.terminate(); await asyncio.wait_for(proc.wait(), timeout=1)
                except Exception:
                    try: proc.kill()
                    except Exception: pass


async def validate_xray(items):
    sem = asyncio.Semaphore(XRAY_CONCURRENCY)
    return await asyncio.gather(*(_probe_one(dict(x), sem) for x in items))
