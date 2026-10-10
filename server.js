// Stalker-Portal to M3U playlist server (Node.js 18+)
// Run:   node server.js
// Open:  http://localhost:8080/playlist.m3u8
// Other devices on your network can use http://<this-computer-ip>:8080/playlist.m3u8

const http = require('http');
const crypto = require('crypto');
const { Readable } = require('stream');
const { once } = require('events');

// ============ CONFIGURATION ============
const config = {
    host: 'watch.doordarshan.cc', // hostname only, no http:// and no path
    mac_address: '',
    serial_number: '',
    device_id: '',
    device_id_2: '',
    stb_type: 'MAG250',
    api_signature: '263',
    // Optional: set a secret and use /playlist.m3u8?key=YOURSECRET so others can't use your link.
    secret_key: '',
    // false = redirect the player to the stream server (fine when the player is on the same network as this server).
    // true  = this server fetches the video and relays it (needed when stream links are tied to the server's IP).
    proxy_streams: false,
};
const PORT = process.env.PORT || 8080;
const TOKEN_TTL_MS = 5 * 60 * 1000;
// ======================================

const md5 = s => crypto.createHash('md5').update(s).digest('hex');
config.hw_version = '1.7-BD-' + md5(config.mac_address).substring(0, 2).toUpperCase();
config.hw_version_2 = md5(config.serial_number.toLowerCase() + config.mac_address.toLowerCase());

let cached = { token: '', profile: {}, account_info: {}, time: 0 };
let lastError = '';

const log = m => console.log(`${new Date().toISOString()} - ${m}`);
const base = () => `http://${config.host}/stalker_portal`;

function getHeaders(token = '') {
    const h = {
        'Cookie': `mac=${config.mac_address}; stb_lang=en; timezone=GMT`,
        'Referer': `${base()}/c/`,
        'User-Agent': 'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3',
        'X-User-Agent': `Model: ${config.stb_type}; Link: WiFi`,
    };
    if (token) h['Authorization'] = `Bearer ${token}`;
    return h;
}

async function apiGet(name, url, token = '') {
    try {
        log(`${name}: ${url.substring(0, 140)}`);
        const res = await fetch(url, { headers: getHeaders(token) });
        const text = await res.text();
        if (!res.ok) {
            lastError = `${name} -> HTTP ${res.status} | ${text.substring(0, 200)}`;
            log(lastError);
            return null;
        }
        try {
            return JSON.parse(text);
        } catch {
            lastError = `${name} -> non-JSON reply: ${text.substring(0, 200)}`;
            log(lastError);
            return null;
        }
    } catch (e) {
        lastError = `${name} -> fetch error: ${e.message}`;
        log(lastError);
        return null;
    }
}

async function getToken() {
    const data = await apiGet('getToken', `${base()}/server/load.php?type=stb&action=handshake&token=&JsHttpRequest=1-xml`);
    const token = data?.js?.token || '';
    if (!token && data) {
        lastError = `getToken -> portal replied without a token: ${JSON.stringify(data).substring(0, 300)}`;
        log(lastError);
    }
    return token;
}

async function auth(token) {
    const metrics = { mac: config.mac_address, model: '', type: 'STB', uid: '', device: '', random: '' };
    const url = `${base()}/server/load.php?type=stb&action=get_profile`
        + `&hd=1&ver=${encodeURIComponent('ImageDescription: 0.2.18-r14-pub-250; PORTAL version: 5.5.0; API Version: 328;')}`
        + `&num_banks=2&sn=${config.serial_number}`
        + `&stb_type=${config.stb_type}&client_type=STB&image_version=218&video_out=hdmi`
        + `&device_id=${config.device_id}&device_id2=${config.device_id_2}`
        + `&signature=&auth_second_step=1&hw_version=${config.hw_version}`
        + `&not_valid_token=0&metrics=${encodeURIComponent(JSON.stringify(metrics))}`
        + `&hw_version_2=${config.hw_version_2}&api_signature=${config.api_signature}`
        + `&prehash=&JsHttpRequest=1-xml`;
    return (await apiGet('auth', url, token))?.js || {};
}

async function handShake(token) {
    const data = await apiGet('handShake', `${base()}/server/load.php?type=stb&action=handshake&token=${token}&JsHttpRequest=1-xml`);
    return data?.js?.token || '';
}

async function getAccountInfo(token) {
    return (await apiGet('getAccountInfo', `${base()}/server/load.php?type=account_info&action=get_main_info&JsHttpRequest=1-xml`, token))?.js || {};
}

async function getGenres(token) {
    const data = await apiGet('getGenres', `${base()}/server/load.php?type=itv&action=get_genres&JsHttpRequest=1-xml`, token);
    return Array.isArray(data?.js) ? data.js : [];
}

async function getStreamURL(cmd, token) {
    const url = `${base()}/server/load.php?type=itv&action=create_link&cmd=${encodeURIComponent(cmd)}&JsHttpRequest=1-xml`;
    const data = await apiGet('getStreamURL', url, token);
    return (data?.js?.cmd || '').replace(/^(ffmpeg|ffrt\d?|auto)\s+/i, '').trim();
}

async function genToken() {
    if (cached.token && Date.now() - cached.time < TOKEN_TTL_MS) return cached;
    lastError = '';
    const token = await getToken();
    if (!token) return { token: '' };
    const profile = await auth(token);
    const newToken = await handShake(token);
    const finalToken = newToken || token;
    const account_info = await getAccountInfo(finalToken);
    cached = { token: finalToken, profile, account_info, time: Date.now() };
    return cached;
}

const keyParam = () => (config.secret_key ? `&key=${encodeURIComponent(config.secret_key)}` : '');
const relaySecret = () => config.secret_key || md5(config.serial_number + config.device_id + config.mac_address);
const sign = u => crypto.createHmac('sha256', relaySecret()).update(u).digest('hex');
const relayLink = (origin, u) => `${origin}/relay?p=${Buffer.from(u).toString('base64url')}&sig=${sign(u)}${keyParam()}`;

function rewriteHls(body, baseUrl, origin) {
    const abs = r => { try { return new URL(r, baseUrl).toString(); } catch { return r; } };
    return body.split(/\r\n|\r|\n/).map(line => {
        const t = line.trim();
        if (!t) return line;
        if (t.startsWith('#')) return line.replace(/URI="([^"]+)"/g, (m, u) => `URI="${relayLink(origin, abs(u))}"`);
        return relayLink(origin, abs(t));
    }).join('\n');
}

// Fetch `target` from this server and pass it on. HLS playlists are rewritten so segments
// also come through here; anything else is streamed straight through.
async function relay(res, target, origin) {
    const ac = new AbortController();
    res.on('close', () => ac.abort());
    try {
        const up = await fetch(target, { headers: getHeaders(), redirect: 'follow', signal: ac.signal });
        const ctype = up.headers.get('content-type') || '';
        if (!up.body) return send(res, up.status, '');
        const reader = up.body.getReader();
        const first = await reader.read();
        const head = first.value ? Buffer.from(first.value.subarray(0, 7)).toString() : '';
        const isHls = /mpegurl/i.test(ctype) || /\.m3u8($|\?)/i.test(up.url) || head === '#EXTM3U';
        if (isHls && up.ok) {
            const chunks = first.value ? [Buffer.from(first.value)] : [];
            for (;;) {
                const { done, value } = await reader.read();
                if (done) break;
                chunks.push(Buffer.from(value));
            }
            return send(res, 200, rewriteHls(Buffer.concat(chunks).toString('utf8'), up.url, origin), 'application/vnd.apple.mpegurl');
        }
        res.writeHead(up.status, { 'Content-Type': ctype || 'application/octet-stream', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' });
        if (first.value) res.write(first.value);
        for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            if (!res.write(value)) await once(res, 'drain');
        }
        res.end();
    } catch (e) {
        if (!res.headersSent) send(res, 502, `Stream fetch error: ${e.message}`);
        else res.end();
    }
}

const clean = s => String(s ?? '').replace(/"/g, "'").replace(/[\r\n]+/g, ' ').trim();

function infoEntry(name, value) {
    return [
        `#EXTINF:-1 tvg-name="${clean(name)}" group-title="Portal | Info",${clean(name)} • ${clean(value)}`,
        'https://tg-aadi.vercel.app/intro.m3u8',
    ];
}

function buildM3U(channels, profile, account_info, origin, clientIp) {
    const m3u = ['#EXTM3U', `# Total Channels => ${channels.length}`, ''];

    let max_online = 'Unknown';
    if (profile.storages && Object.keys(profile.storages).length > 0) {
        max_online = Object.values(profile.storages)[0].max_online || 'Unknown';
    }
    m3u.push(...infoEntry('IP', profile.ip || 'Unknown'));
    m3u.push(...infoEntry('User IP', clientIp));
    m3u.push(...infoEntry('Portal', config.host));
    m3u.push(...infoEntry('Created', profile.created || 'Unknown'));
    m3u.push(...infoEntry('End date', account_info.end_date || 'Unknown'));
    m3u.push(...infoEntry('Tariff Plan', account_info.tariff_plan || 'Unknown'));
    m3u.push(...infoEntry('Max Connection', max_online));

    for (const ch of channels) {
        if (!ch.cmd) continue;
        const encoded = Buffer.from(ch.cmd, 'utf8').toString('base64url');
        const logo = ch.logo ? `${base()}/misc/logos/320/${ch.logo}` : '';
        m3u.push(`#EXTINF:-1 tvg-id="${clean(ch.tvgid)}" tvg-name="${clean(ch.name)}" tvg-logo="${logo}" group-title="${clean(ch.title)}",${clean(ch.name)}`);
        m3u.push(`${origin}/stream/${encoded}.m3u8${config.secret_key ? '?key=' + encodeURIComponent(config.secret_key) : ''}`);
    }
    return m3u.join('\n');
}

function send(res, status, body, type = 'text/plain; charset=utf-8') {
    res.writeHead(status, { 'Content-Type': type, 'Access-Control-Allow-Origin': '*' });
    res.end(body);
}

async function handle(req, res) {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const isPlaylist = url.pathname === '/playlist.m3u8';
    const streamMatch = url.pathname.match(/^\/stream\/([^/]+)\.m3u8$/);
    const isRelay = url.pathname === '/relay';
    if (!isPlaylist && !streamMatch && !isRelay) return send(res, 404, 'Not Found');

    if (config.secret_key && url.searchParams.get('key') !== config.secret_key) return send(res, 403, 'Forbidden');
    const origin = `http://${req.headers.host}`;

    if (isRelay) {
        let target = '';
        try { target = Buffer.from(url.searchParams.get('p') || '', 'base64url').toString('utf8'); } catch {}
        const given = Buffer.from(url.searchParams.get('sig') || '');
        const want = Buffer.from(target ? sign(target) : '');
        if (!/^https?:\/\//i.test(target) || given.length !== want.length || !crypto.timingSafeEqual(given, want)) {
            return send(res, 403, 'Invalid relay link');
        }
        return relay(res, target, origin);
    }

    const { token, profile, account_info } = await genToken();
    if (!token) return send(res, 500, `Token generation failed. Reason: ${lastError || 'empty token in portal reply'}`);

    if (isPlaylist) {
        const data = await apiGet('getAllChannels', `${base()}/server/load.php?type=itv&action=get_all_channels&JsHttpRequest=1-xml`, token);
        const items = data?.js?.data;
        if (!Array.isArray(items)) {
            cached.token = '';
            return send(res, 502, `Failed to fetch channels. ${lastError}`);
        }
        const genres = await getGenres(token);
        const groupMap = {};
        genres.forEach(g => { groupMap[g.id] = g.title || 'Other'; });
        const channels = items.map(i => ({
            name: i.name || 'Unknown',
            cmd: i.cmd || '',
            tvgid: i.xmltv_id || '',
            logo: i.logo || '',
            title: groupMap[i.tv_genre_id] || 'Other',
        }));
        const clientIp = req.socket.remoteAddress || 'Unknown';
        return send(res, 200, buildM3U(channels, profile, account_info, origin, clientIp), 'application/vnd.apple.mpegurl');
    }

    let cmd;
    try {
        cmd = Buffer.from(streamMatch[1], 'base64url').toString('utf8');
    } catch {
        return send(res, 400, 'Invalid channel reference');
    }
    const stream = await getStreamURL(cmd, token);
    if (!stream) {
        cached.token = '';
        return send(res, 502, `No stream URL received. ${lastError}`);
    }
    if (config.proxy_streams) return relay(res, stream, origin);
    res.writeHead(302, { Location: stream });
    res.end();
}

http.createServer((req, res) => {
    handle(req, res).catch(e => {
        log(`Unexpected error: ${e.stack || e.message}`);
        send(res, 500, `Internal Server Error: ${e.message}`);
    });
}).listen(PORT, () => log(`Listening on http://localhost:${PORT}/playlist.m3u8`));
