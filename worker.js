/**
 * Trae + WorkBuddy 每日签到 —— Cloudflare Worker（单文件）
 *
 * 一个 Worker 同时管理两个平台的每日签到：一套部署、一个控制台、一条定时任务。
 * 两个平台各自独立完成登录态维护与签到，账号数据存在同一个 KV 里，
 * 按 trae: / wb: 前缀隔离，互不干扰。
 *
 * 代码结构（三段）：
 *   1. Trae 模块      设备身份、抖音扫码授权、签到与积分查询
 *   2. WorkBuddy 模块 扫码授权、令牌轮换、签到
 *   3. 外壳           绑定适配 + 路由分发 + 控制台页面
 *
 * 环境绑定（两个平台共用一个 KV，按 trae: / wb: 前缀隔离）：
 *
 *   KV 绑定    KV            （一个命名空间即可）
 *   Secret     MASTER_KEY    32 字节随机值的 base64，两个平台共用
 *   Secret     ADMIN_TOKEN   控制台登录密码
 *   Secret     CRON_SECRET   （可选）/cron 独立口令，缺省回落到 ADMIN_TOKEN
 *
 * 只认这几个名字，不需要按平台拆成多份绑定。
 *
 * 路由：
 *   /                     控制台（Trae / WorkBuddy 两个标签页）
 *   /cron                 定时入口，两个平台依次签到
 *   /api/ping             密码校验
 *   /api/run-all          两个平台一起签
 *   /trae/api/*           Trae 的管理接口
 *   /wb/api/*             WorkBuddy 的管理接口
 *   /oauth/callback       Trae 扫码回调（授权链接里写死这个路径，必须在根）
 *
 * Cron 配置（Cloudflare 的 cron 走 UTC，比北京时间慢 8 小时）：
 *   北京 08:10 = UTC 00:10
 *   crons = ["10 0 * * *"]
 * 一次触发里两个平台会依次各跑一遍，所以只写一条就够。
 * 签到本身是幂等的（今天签过就跳过），想多兜几次只需在数组里多加一条时间。
 */


/* ================================================================== */
/* 模块一：Trae —— 设备身份 / 扫码授权 / 签到 */
/* ================================================================== */

const Trae = (() => {
const API = 'https://api.trae.cn';

const EP = {
  claim: '/trae/api/v2/ug/checkin_credits/claim',
  status: '/trae/api/v2/ug/checkin_credits/status',
  entitle: '/trae/api/v2/pay/user_current_entitlement_list',
  exchange: '/trae/api/v3/oauth/ExchangeToken',
  exchangeLegacy: 'https://api.trae.com.cn/cloudide/api/v3/trae/oauth/ExchangeToken',
};

const CLIENT_ID_IDE = 'ono9krqynydwx5';
const CLIENT_ID_OLD = 'en1oxy7wnw8j9n';
const IDE_VERSION = '1.107.1';
const UA = 'Trae/' + IDE_VERSION;

/* 扫码登录（网页授权）用到的固定参数，随官网版本更新而变 */
const AUTHORIZE_BASE = 'https://www.trae.cn';
const OAUTH_APP_ID = '6eefa01c-1036-4c7e-9ca5-d891f63bfcd8';
const OAUTH_APP_VERSION = '3.3.100';
const OAUTH_PLUGIN_VERSION = '2.3.83560';

/* 回调地址：官网只认 http://127.0.0.1:<端口>，换成域名（包括 localhost、https、无端口）
   都会让登录页立刻显示「登录失败 · 网络错误」，与扫码无关。
   所以固定指向本机一个没有服务的端口：登录完成后浏览器会停在一个打不开的页面，
   用户把地址栏里的整段链接粘回控制台即可完成绑定。 */
const CALLBACK_LOCAL = 'http://127.0.0.1:17388/authorize';
/* Trae 产品线的授权参数：client_id 与 platform 必须成对，随官网版本更新而变 */
const TRAE_LINE = { authFrom: 'trae', clientId: 'ono9krqynydwx5', platform: 'IDE_PC', label: 'Trae' };
const LOGIN_TTL = 900; // 登录会话 15 分钟
const LOGIN_LATEST = 'login:latest';

const REQ_BODY = '{"req_source": 1}';
const CODE_OK = 0;
const CODE_ALREADY = 9095;
const CODE_RATE = 9074;
const AUTH_FAIL_CODES = [1001, 1002, 401, 403];
const COOLDOWN_MIN = 55;
const PEAK_COOLDOWN_MIN = 12;

/* ------------------------------------------------------------------ */
/* 编码工具                                                            */
/* ------------------------------------------------------------------ */

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64encode(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function b64decode(str) {
  const bin = atob(String(str).replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlEncode(buf) {
  return b64encode(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  return b64decode(s + '='.repeat((4 - (s.length % 4)) % 4));
}

function randomId(bytes = 12) {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(bytes)));
}

function randomHex(bytes = 16) {
  const b = crypto.getRandomValues(new Uint8Array(bytes));
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}

/** 定长比较，避免口令被时序侧信道猜出来 */
function timingSafeEqual(a, b) {
  const x = enc.encode(String(a ?? ''));
  const y = enc.encode(String(b ?? ''));
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

/* ------------------------------------------------------------------ */
/* 加密：AES-256-GCM + 每条记录随机 salt，密钥由主密钥 HKDF 派生        */
/* ------------------------------------------------------------------ */

async function deriveKey(env, salt) {
  const raw = env.TRAE_MASTER_KEY;
  if (!raw) throw new Error('缺少 MASTER_KEY');

  let master;
  try {
    master = b64decode(raw.trim());
  } catch {
    throw new Error('MASTER_KEY 不是合法 base64');
  }
  if (master.length !== 32) throw new Error('MASTER_KEY 必须是 32 字节（base64 后 44 字符）');

  const base = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('trae-signin/v1/account') },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function sealRecord(env, obj) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(env, salt);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
  return JSON.stringify({ v: 1, s: b64encode(salt), i: b64encode(iv), d: b64encode(ct) });
}

async function openRecord(env, text) {
  const box = JSON.parse(text);
  if (box.v !== 1) throw new Error('不认识的记录版本');
  const key = await deriveKey(env, b64decode(box.s));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64decode(box.i) }, key, b64decode(box.d));
  return JSON.parse(dec.decode(pt));
}

/* ------------------------------------------------------------------ */
/* ECDSA：P-256 / SHA-256，输出 base64(DER)，低 s 归一化               */
/* ------------------------------------------------------------------ */

const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

function pemToDer(pem) {
  const body = String(pem)
    .replace(/-----[^-]+-----/g, '')
    .replace(/\s+/g, '');
  return b64decode(body);
}

function bytesToBig(bytes) {
  let h = '';
  for (const b of bytes) h += b.toString(16).padStart(2, '0');
  return h ? BigInt('0x' + h) : 0n;
}

function bigToBytes(x) {
  let h = x.toString(16);
  if (h.length % 2) h = '0' + h;
  const out = [];
  for (let i = 0; i < h.length; i += 2) out.push(parseInt(h.slice(i, i + 2), 16));
  return Uint8Array.from(out);
}

/** DER INTEGER：去前导零，最高位为 1 时补 0x00 保证正整数 */
function derInt(bytes) {
  const arr = Array.from(bytes);
  let i = 0;
  while (i < arr.length - 1 && arr[i] === 0) i++;
  let v = arr.slice(i);
  if (v.length === 0 || (v[0] & 0x80)) v = [0, ...v];
  return [0x02, v.length, ...v];
}

/** DER SEQUENCE { INTEGER r, INTEGER s } —— 长度均 < 128，单字节长度即可 */
function derSig(rBytes, sBytes) {
  const body = derInt(rBytes).concat(derInt(sBytes));
  return Uint8Array.from([0x30, body.length, ...body]);
}

/** 简易 DER TLV 读取，只解决本文件需要的结构 */
function derNext(buf, i) {
  const tag = buf[i++];
  let len = buf[i++];
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let k = 0; k < n; k++) len = len * 256 + buf[i++];
  }
  return { tag, val: buf.subarray(i, i + len), next: i + len };
}

/** 从 SEC1（BEGIN EC PRIVATE KEY）里取私钥标量 */
function sec1Scalar(pem) {
  const der = pemToDer(pem);
  const outer = derNext(der, 0);
  if (outer.tag !== 0x30) throw new Error('SEC1 私钥结构异常');
  let i = 0;
  let d = null;
  while (i < outer.val.length) {
    const node = derNext(outer.val, i);
    if (node.tag === 0x04 && !d) d = node.val;
    i = node.next;
  }
  if (!d) throw new Error('SEC1 私钥里没找到私钥标量');
  return d;
}

/** 从 SPKI 公钥里取 P-256 的 x / y */
function spkiPoint(pem) {
  const der = pemToDer(pem);
  const outer = derNext(der, 0);
  if (outer.tag !== 0x30) throw new Error('公钥结构异常');
  const alg = derNext(outer.val, 0);
  const bits = derNext(outer.val, alg.next);
  if (bits.tag !== 0x03 || bits.val[0] !== 0 || bits.val[1] !== 0x04) {
    throw new Error('公钥不是未压缩的 P-256 点');
  }
  return { x: bits.val.subarray(2, 34), y: bits.val.subarray(34, 66) };
}

const ecdsaAlg = { name: 'ECDSA', namedCurve: 'P-256' };

/** 导入设备私钥：优先 PKCS#8，失败则按 SEC1 + 公钥补 x/y 走 JWK */
async function importPrivateKey(pem, pubPem) {
  if (!pem) throw new Error('缺少设备私钥');
  try {
    return await crypto.subtle.importKey('pkcs8', pemToDer(pem), ecdsaAlg, false, ['sign']);
  } catch (e) {
    if (!pubPem) throw new Error('私钥不是 PKCS#8，且没有公钥可用于 SEC1 转换');
    const d = sec1Scalar(pem);
    const { x, y } = spkiPoint(pubPem);
    return crypto.subtle.importKey(
      'jwk',
      { kty: 'EC', crv: 'P-256', d: b64urlEncode(d), x: b64urlEncode(x), y: b64urlEncode(y), ext: true },
      ecdsaAlg,
      false,
      ['sign']
    );
  }
}

/** 签名 canonical 串，返回 base64(DER)。低 s 归一化，与官方客户端的算法对齐。 */
async function ecSign(pem, data, pubPem) {
  const key = await importPrivateKey(pem, pubPem);
  const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, data));
  let r = bytesToBig(raw.subarray(0, 32));
  let s = bytesToBig(raw.subarray(32));
  if (s > P256_N >> 1n) s = P256_N - s; // 低 s 归一化
  return b64encode(derSig(bigToBytes(r), bigToBytes(s)));
}

/* ------------------------------------------------------------------ */
/* 与 Trae 服务端交互                                                   */
/* ------------------------------------------------------------------ */

async function traeFetch(path, { method = 'POST', headers = {}, body = '{}', timeout = 20000 } = {}) {
  const url = path.startsWith('http') ? path : API + path;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json', ...headers },
      body: method === 'GET' ? undefined : body,
      signal: ctrl.signal,
    });
    const text = await res.text();
    let json = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* 非 JSON 响应留给调用方从 text 里看 */
    }
    return { status: res.status, json, text };
  } finally {
    clearTimeout(timer);
  }
}

/** 签到/积分接口通用头：缺设备头会被服务端拒成 9074 */
function ugHeaders(token, acct) {
  const h = {
    Authorization: 'Cloud-IDE-JWT ' + token,
    'X-User-Region': 'CN',
    'User-Agent': UA,
    'Content-Type': 'application/json',
  };
  const did = String(acct?.deviceId ?? '').trim();
  if (did) h['x-device-id'] = did;
  h['x-device-type'] = String(acct?.deviceType || 'Windows');
  h['x-os-version'] = String(acct?.osVersion || '10.0.19045');
  h['x-app-version'] = IDE_VERSION;
  const brand = String(acct?.deviceBrand ?? '').trim();
  if (brand) h['x-device-brand'] = brand;
  return h;
}

/** 从 JWT 里取过期时间（秒）。兼容自定义声明 TokenExpireAt（秒/毫秒都可能） */
function jwtExp(token) {
  try {
    const json = JSON.parse(dec.decode(b64urlDecode(String(token).split('.')[1])));
    let v = Number(json.exp || json.TokenExpireAt || 0) || 0;
    if (v > 1e12) v = Math.floor(v / 1000); // 毫秒归一化
    return v;
  } catch {
    return 0;
  }
}

/** 构造设备证明 (DeviceProof, DeviceInfo) */
async function buildProof(acct, path, clientId, platformCode, refreshToken) {
  const ts = Math.floor(Date.now() / 1000);
  const nonce = randomHex(16);
  const canonical = ['POST', path, clientId, refreshToken, String(ts), nonce].join('\n');
  const signature = await ecSign(acct.privateKeyPem, enc.encode(canonical), acct.publicKeyPem);
  return {
    proof: { Timestamp: ts, Nonce: nonce, Signature: signature },
    info: {
      DeviceID: String(acct.deviceId || ''),
      MachineID: String(acct.machineId || ''),
      PlatformCode: platformCode,
      DeviceType: 'PC',
      DeviceName: String(acct.deviceName || 'PC'),
      DeviceModel: String(acct.deviceModel || ''),
      ClientVersion: IDE_VERSION,
      DevicePublicKey: String(acct.publicKeyPem || ''),
      DeviceBrand: String(acct.deviceBrand || ''),
      DeviceCPU: '',
      OSInfo: String(acct.osInfo || 'Windows'),
      OSVersion: String(acct.osVersion || '10.0.19045'),
    },
  };
}

function explainRefreshErr(json, text) {
  const err = (json?.ResponseMetadata?.Error) || {};
  const code = err.Code;
  const msg = (err.Data && err.Data['__Message.error']) || err.Message || String(text).slice(0, 200);
  const hint =
    {
      20101: 'refreshToken 已失效或被别处轮换，请删掉该账号重新扫码登录',
      10101: 'refreshToken 与当前产品线不匹配，请用对应按钮重新扫码登录',
      20405: '服务端要求设备证明，但该账号缺少设备密钥，请删掉后重新扫码登录',
      20403: '设备密钥与令牌不匹配，请删掉该账号重新扫码登录',
    }[code] || '';
  return `code=${code ?? '?'} ${msg}${hint ? '（' + hint + '）' : ''}`;
}

/**
 * 用 refreshToken 换新的双令牌。
 * 主接口要求设备证明，按「钥匙 × 产品线」三组组合依次尝试；
 * 账号没有设备材料时只能走备用端点（大概率失败，但报错更具体）。
 */
async function refreshTokens(acct) {
  const rt = String(acct.refreshToken || '').trim();
  if (!rt) throw new Error('账号没有 refreshToken');

  const hasKeys = !!(acct.privateKeyPem && acct.publicKeyPem);

  if (!hasKeys) {
    const body = JSON.stringify({
      ClientID: CLIENT_ID_OLD,
      RefreshToken: rt,
      ClientSecret: '-',
      UserID: '',
    });
    const r = await traeFetch(EP.exchangeLegacy, {
      headers: { Accept: 'application/json', 'User-Agent': UA },
      body,
    });
    const token = r.json?.Result?.Token;
    if (r.status >= 400 || !token) throw new Error('刷新令牌失败: ' + explainRefreshErr(r.json, r.text));
    return {
      accessToken: token,
      refreshToken: r.json.Result.RefreshToken || rt,
    };
  }

  const combos = [
    [acct.clientId || CLIENT_ID_IDE, acct.platformCode || 'IDE_PC'],
    [CLIENT_ID_OLD, 'IDE_PC'],
    [CLIENT_ID_OLD, 'SOLO_PC'],
  ].filter((v, i, arr) => arr.findIndex((x) => x[0] === v[0] && x[1] === v[1]) === i);

  let lastErr = null;
  for (const [clientId, platformCode] of combos) {
    let built;
    try {
      built = await buildProof(acct, EP.exchange, clientId, platformCode, rt);
    } catch (e) {
      throw new Error('设备签名失败（检查设备私钥）: ' + e.message);
    }
    const body = JSON.stringify({
      ClientID: clientId,
      ClientSecret: '',
      RefreshToken: rt,
      DeviceInfo: built.info,
      DeviceProof: built.proof,
      IDEVersion: IDE_VERSION,
    });
    const r = await traeFetch(EP.exchange, {
      headers: { 'x-cloudide-token': '' },
      body,
    });
    const token = r.json?.Result?.Token;
    if (r.status < 400 && token) {
      return { accessToken: token, refreshToken: r.json.Result.RefreshToken || rt };
    }
    lastErr = explainRefreshErr(r.json, r.text);
    // 只有「不匹配」类错误才值得换一组钥匙，其它错误直接抛
    const raw = String(r.text || '');
    if (!raw.includes('10101') && !raw.includes('20403')) break;
  }
  throw new Error('刷新令牌失败: ' + (lastErr || '未知错误'));
}

/** 提交签到：0 成功 / 9095 今日已签 / 9074 限流 */
async function claim(token, acct) {
  const r = await traeFetch(EP.claim, { headers: ugHeaders(token, acct), body: REQ_BODY });
  if (!r.json) return { status: r.status, code: '?', msg: String(r.text).slice(0, 160), points: null };
  const data = r.json.data;
  const points = data && typeof data === 'object' ? data.points ?? null : null;
  return {
    status: r.status,
    code: r.json.code ?? -1,
    msg: r.json.message || String(r.text).slice(0, 160),
    points,
  };
}

/** 查询今日签到状态：checked_in / credits */
async function statusOf(token, acct) {
  const r = await traeFetch(EP.status, { headers: ugHeaders(token, acct), body: REQ_BODY });
  if (!r.json) return { ok: false, code: '?', raw: String(r.text).slice(0, 160) };
  if (r.status >= 400) return { ok: false, code: r.json.code ?? -1, raw: String(r.text).slice(0, 160) };
  return {
    ok: true,
    checked: r.json.checked_in === true,
    credits: typeof r.json.credits === 'number' ? r.json.credits : null,
    enable: r.json.enable ?? null,
    code: r.json.code ?? -1,
  };
}

/** 查积分余额：优先 usage_summary，再按 entitlement 包求和兜底 */
async function creditsOf(token, acct) {
  const r = await traeFetch(EP.entitle, { headers: ugHeaders(token, acct), body: '{"require_usage": true}' });
  const d = r.json;
  if (!d) return null;
  const root = d.data || d;
  const us = root.usage_summary || {};
  const total = Number(us.total_amount || 0);
  const used = Number(us.consumed_amount || 0);
  if (total > 0) return total - used;
  const packs = root.user_entitlement_pack_list || [];
  let sum = 0;
  let found = false;
  for (const p of packs) {
    const limit = Number(p?.entitlement_base_info?.quota?.credits_limit || 0);
    const consumed = Number(p?.usage?.credits_amount || 0);
    if (limit > 0) {
      found = true;
      sum += Math.max(limit - consumed, 0);
    }
  }
  return found ? sum : null;
}

/* ------------------------------------------------------------------ */
/* KV 读写                                                             */
/* ------------------------------------------------------------------ */

const acctKey = (id) => `acct:${id}`;
const INDEX_KEY = 'index:accounts';

async function listAccounts(env) {
  const raw = await env.TRAE_KV.get(INDEX_KEY);
  return raw ? JSON.parse(raw) : [];
}

async function saveIndex(env, list) {
  await env.TRAE_KV.put(INDEX_KEY, JSON.stringify(list));
}

async function getAccount(env, id) {
  const raw = await env.TRAE_KV.get(acctKey(id));
  if (!raw) return null;
  return openRecord(env, raw);
}

async function putAccount(env, acct) {
  await env.TRAE_KV.put(acctKey(acct.id), await sealRecord(env, acct));
}

/* ------------------------------------------------------------------ */
/* 时间与账号状态辅助                                                   */
/* ------------------------------------------------------------------ */

const bjDay = (ms = Date.now()) => new Date(ms + 8 * 3600e3).toISOString().slice(0, 10);
const bjHour = (ms = Date.now()) => new Date(ms + 8 * 3600e3).getUTCHours();

/** 早窗（北京时间 0 点）冷却更短，好让下一轮还能在窗口里补签 */
function cooldownMinutes() {
  return bjHour() === 0 ? PEAK_COOLDOWN_MIN : COOLDOWN_MIN;
}

/* ------------------------------------------------------------------ */
/* 单个账号的完整签到流程                                               */
/* ------------------------------------------------------------------ */

async function signinOne(env, acct, { force = false } = {}) {
  const now = Date.now();
  const today = bjDay(now);
  const base = { id: acct.id, label: acct.label };

  if (!force && Number(acct.cooldownUntil || 0) > now) {
    const left = Math.ceil((acct.cooldownUntil - now) / 60000);
    return { ...base, state: 'cooldown', msg: `限流冷却中，约 ${left} 分钟` };
  }

  if (!force && acct.lastOkDate === today) {
    return { ...base, state: 'skipped', msg: '今日已完成' };
  }

  // 1) 拿一个可用的 accessToken：还没过期就直接用，避免无谓轮换
  let token = String(acct.accessToken || '');
  const exp = jwtExp(token);
  const usable = token && (!exp || exp * 1000 - now > 120000);

  if (!usable) {
    try {
      const t = await refreshTokens(acct);
      token = t.accessToken;
      acct.refreshToken = t.refreshToken;
      acct.accessToken = token;
      acct.accessExp = jwtExp(token);
      acct.tokenRefreshedAt = now;
      await putAccount(env, acct); // 先落盘：令牌链不能断
    } catch (e) {
      acct.lastState = 'token_dead';
      acct.lastMsg = e.message;
      acct.lastRun = now;
      await putAccount(env, acct);
      return { ...base, state: 'token_dead', msg: e.message };
    }
  }

  // 2) 提交签到（鉴权类错误刷新一次再试）
  let res = await claim(token, acct);

  if (AUTH_FAIL_CODES.includes(res.code)) {
    try {
      const t = await refreshTokens(acct);
      token = t.accessToken;
      acct.refreshToken = t.refreshToken;
      acct.accessToken = token;
      acct.accessExp = jwtExp(token);
      await putAccount(env, acct);
      res = await claim(token, acct);
    } catch (e) {
      acct.lastState = 'token_dead';
      acct.lastMsg = e.message;
      acct.lastRun = now;
      await putAccount(env, acct);
      return { ...base, state: 'token_dead', msg: e.message };
    }
  }

  acct.lastRun = now;

  // 3) 限流：换个假设备号也没用，9074 会原样返回，按账号冷却等下轮
  if (res.code === CODE_RATE || res.status === 429 || res.status >= 500) {
    const mins = cooldownMinutes();
    acct.cooldownUntil = now + mins * 60000;
    acct.lastState = 'rate';
    acct.lastMsg = `限流 9074，冷却 ${mins} 分钟`;
    await putAccount(env, acct);
    return { ...base, state: 'rate', msg: acct.lastMsg };
  }

  // 4) 今日已签
  if (res.code === CODE_ALREADY) {
    acct.lastState = 'already';
    acct.lastMsg = '今日已签';
    acct.lastOkDate = today;
    acct.cooldownUntil = 0;
    const st = await statusOf(token, acct).catch(() => null);
    if (st?.ok) {
      acct.credits = st.credits ?? acct.credits ?? null;
      acct.checkedIn = true;
    }
    await putAccount(env, acct);
    return { ...base, state: 'already', msg: '今日已签', credits: acct.credits ?? null };
  }

  // 5) 其它失败
  if (res.code !== CODE_OK) {
    acct.lastState = 'error';
    acct.lastMsg = `签到失败 code=${res.code} ${res.msg ?? ''}`.trim();
    await putAccount(env, acct);
    return { ...base, state: 'error', msg: acct.lastMsg };
  }

  // 6) code=0 未必真到账：用同一 deviceId 回查 checked_in 是否翻转
  let confirmed = false;
  let credits = null;
  try {
    const st = await statusOf(token, acct);
    if (st.ok) {
      confirmed = st.checked === true;
      credits = st.credits;
    }
  } catch {
    /* 回查失败按未确认处理，交给下轮 cron */
  }

  if (!confirmed) {
    const bal = await creditsOf(token, acct).catch(() => null);
    acct.lastState = 'pending';
    acct.lastMsg = '已提交，但回查未确认，等下轮再试';
    acct.credits = bal ?? credits ?? acct.credits ?? null;
    acct.cooldownUntil = now + 12 * 60000;
    await putAccount(env, acct);
    return { ...base, state: 'pending', msg: acct.lastMsg, credits: acct.credits ?? null };
  }

  const bal = await creditsOf(token, acct).catch(() => null);
  acct.lastState = 'checked';
  acct.lastMsg = res.points ? `+${res.points} 积分` : '签到成功';
  acct.lastOkDate = today;
  acct.lastCredit = res.points ?? null;
  acct.totalCredit = (acct.totalCredit ?? 0) + (Number(res.points) || 0);
  acct.totalSigned = (acct.totalSigned ?? 0) + 1;
  acct.credits = bal ?? credits ?? acct.credits ?? null;
  acct.checkedIn = true;
  acct.cooldownUntil = 0;
  await putAccount(env, acct);

  return {
    ...base,
    state: 'checked',
    msg: acct.lastMsg,
    credits: acct.credits ?? null,
    points: res.points ?? null,
  };
}

/* ------------------------------------------------------------------ */
/* 页面与鉴权辅助                                                       */
/* ------------------------------------------------------------------ */

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

function requireAdmin(request, env) {
  const url = new URL(request.url);
  const given =
    request.headers.get('X-Admin-Token') ||
    (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '') ||
    url.searchParams.get('token');
  if (!env.ADMIN_TOKEN) return { ok: false, res: json({ error: '未配置 ADMIN_TOKEN' }, 500) };
  if (!timingSafeEqual(given, env.ADMIN_TOKEN)) return { ok: false, res: json({ error: '登录密码不正确' }, 401) };
  return { ok: true };
}

function requireCron(request, env) {
  const secret = env.CRON_SECRET || env.ADMIN_TOKEN;
  const url = new URL(request.url);
  const given = request.headers.get('X-Cron-Secret') || url.searchParams.get('key');
  if (!secret) return { ok: false, res: json({ error: '未配置 CRON_SECRET / ADMIN_TOKEN' }, 500) };
  if (!timingSafeEqual(given, secret)) return { ok: false, res: json({ error: '口令不对' }, 401) };
  return { ok: true };
}

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

async function handleRemove(request, env) {
  const body = await readBody(request);
  const id = String(body.id ?? '').trim();
  if (!id) return json({ error: '缺少 id' }, 400);
  await env.TRAE_KV.delete(acctKey(id));
  const list = (await listAccounts(env)).filter((x) => x.id !== id);
  await saveIndex(env, list);
  return json({ ok: true, removed: id });
}

/** 改备注：昵称取不到时就靠这个，改成什么由用户定 */
async function handleRename(request, env) {
  const body = await readBody(request);
  const id = String(body.id ?? '').trim();
  const label = String(body.label ?? '').trim().slice(0, 40);
  if (!id) return json({ error: '缺少 id' }, 400);
  if (!label) return json({ error: '备注不能为空' }, 400);

  const acct = await getAccount(env, id);
  if (!acct) return json({ error: '账号不存在' }, 404);
  acct.label = label;
  await putAccount(env, acct);

  const list = await listAccounts(env);
  await saveIndex(env, list.map((x) => (x.id === id ? { ...x, label } : x)));
  return json({ ok: true, id, label });
}

async function handleList(request, env) {
  const list = await listAccounts(env);
  const out = [];
  const now = Date.now();
  const today = bjDay(now);

  for (const meta of list) {
    const a = await getAccount(env, meta.id);
    if (!a) continue;
    out.push({
      id: a.id,
      label: a.label,
      lastState: a.lastState,
      lastMsg: a.lastMsg,
      lastRun: a.lastRun ? new Date(a.lastRun + 8 * 3600e3).toISOString().replace('Z', ' +08:00') : null,
      lastOkDate: a.lastOkDate ?? null,
      lastCredit: a.lastCredit ?? null,
      credits: typeof a.credits === 'number' ? Math.round(a.credits * 100) / 100 : null,
      totalCredit: a.totalCredit ?? 0,
      totalSigned: a.totalSigned ?? 0,
      cooldownUntil: Number(a.cooldownUntil || 0) > now ? a.cooldownUntil : 0,
      hasKeys: !!(a.privateKeyPem && a.publicKeyPem),
      hasDevice: !!String(a.deviceId || '').trim(),
      // 服务端当场判定，避免前端拿历史状态跨天残留
      today,
      signedToday: a.lastOkDate === today,
      ranToday: a.lastRun ? bjDay(a.lastRun) === today : false,
      // 令牌与私钥永不下发
    });
  }
  return json({ count: out.length, today, accounts: out });
}

async function handleRun(request, env, force) {
  const list = await listAccounts(env);
  const results = [];
  for (const meta of list) {
    const a = await getAccount(env, meta.id);
    if (!a) continue;
    try {
      results.push(await signinOne(env, a, { force }));
    } catch (e) {
      results.push({ id: a.id, label: a.label, state: 'error', msg: e.message });
    }
  }
  return json({
    at: new Date(Date.now() + 8 * 3600e3).toISOString().replace('Z', ' +08:00'),
    accounts: results.length,
    checked: results.filter((r) => r.state === 'checked').length,
    already: results.filter((r) => ['already', 'skipped'].includes(r.state)).length,
    failed: results.filter((r) => ['error', 'token_dead'].includes(r.state)).length,
    cooling: results.filter((r) => ['rate', 'cooldown', 'pending'].includes(r.state)).length,
    results,
  });
}

/* ------------------------------------------------------------------ */
/* 扫码登录（网页授权 → 换令牌）                                        */
/*                                                                     */
/* 账号只能通过扫码添加，不涉及任何本地客户端：                         */
/*   1. 现场生成 P-256 设备密钥对 + 随机 deviceId                       */
/*   2. 拼 /authorization 链接，回调地址固定为 127.0.0.1:<端口>          */
/*   3. 用户用抖音扫码；官网只往本机地址回送 AuthCode                    */
/*   4. 把那段回调链接粘回控制台，用 AuthCode + PKCE + 设备公钥换令牌    */
/*                                                                     */
/* 设备身份由 Worker 自己生成，续期时的设备证明也由自己签名。            */
/* ------------------------------------------------------------------ */

const b64std = (buf) => b64encode(buf);

function toPem(der, label) {
  const b = b64std(der);
  const lines = b.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

/** 生成一套全新的设备身份（私钥 PKCS#8、公钥 SPKI） */
async function genDeviceIdentity() {
  const kp = await crypto.subtle.generateKey(ecdsaAlg, true, ['sign', 'verify']);
  const pkcs8 = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
  const spki = await crypto.subtle.exportKey('spki', kp.publicKey);
  return {
    privateKeyPem: toPem(pkcs8, 'PRIVATE KEY'),
    publicKeyPem: toPem(spki, 'PUBLIC KEY'),
  };
}

/** 15 位数字设备号，首位非 0，与客户端 device_id 形态一致 */
function genDeviceId() {
  const a = crypto.getRandomValues(new Uint8Array(15));
  let s = String(1 + (a[0] % 9));
  for (let i = 1; i < 15; i++) s += String(a[i] % 10);
  return s;
}

/** PKCE：verifier 用 64 位 hex，challenge = base64url(SHA256(verifier)) */
async function pkcePair() {
  const verifier = randomHex(32);
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(verifier));
  return { verifier, challenge: b64urlEncode(digest) };
}

/** URL 编码：保留 '/'，空格转成 %20 */
function qsQuote(v) {
  return encodeURIComponent(String(v)).replace(/%2F/g, '/');
}

function buildAuthorizeUrl(o) {
  const params = [
    ['login_version', '1'],
    ['auth_from', o.authFrom],
    ['login_channel', 'native_ide'],
    ['plugin_version', OAUTH_PLUGIN_VERSION],
    ['auth_type', 'local'],
    ['client_id', o.clientId],
    ['redirect', '0'],
    ['login_trace_id', o.trace],
    ['auth_callback_url', o.callback],
    ['machine_id', o.machineId],
    ['device_id', o.deviceId],
    ['x_device_id', o.deviceId],
    ['x_machine_id', o.machineId],
    ['x_device_brand', 'PC'],
    ['x_device_type', 'Windows'],
    ['x_os_version', '10.0.19045'],
    ['x_env', ''],
    ['x_app_version', OAUTH_APP_VERSION],
    ['x_app_type', 'stable'],
    ['code_challenge', o.challenge],
    ['code_challenge_method', 'S256'],
    ['channel_name', 'common'],
  ];
  return AUTHORIZE_BASE + '/authorization?' + params.map(([k, v]) => k + '=' + qsQuote(v)).join('&');
}

function hostBase(h) {
  const s = String(h || '').trim();
  if (!s) return 'https://api.trae.cn';
  if (/^https?:\/\//i.test(s)) return s.replace(/\/+$/, '');
  return 'https://' + s.replace(/\/+$/, '');
}

/** 递归找 token 字段：兑换响应外层结构各版本不一致 */
function deepFind(obj, keys, depth = 0) {
  if (!obj || typeof obj !== 'object' || depth > 6) return '';
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  for (const v of Object.values(obj)) {
    const r = deepFind(v, keys, depth + 1);
    if (r) return r;
  }
  return '';
}

const ACCESS_KEYS = ['AccessToken', 'access_token', 'token', 'Jwt', 'JWT'];
const REFRESH_KEYS = ['RefreshToken', 'refresh_token'];

/* 用户资料的字段名各版本不统一，按可能性从高到低找昵称 */
const NICK_KEYS = [
  'Nickname', 'nickname', 'NickName', 'nick_name',
  'UserName', 'userName', 'user_name', 'username',
  'ScreenName', 'screen_name',
  'DisplayName', 'displayName', 'display_name',
  'Name', 'name',
];

/** 递归找昵称：只认上面这些字段，避免误抓 DeviceName 之类的值 */
function pickNickname(obj, depth = 0) {
  if (!obj || typeof obj !== 'object' || depth > 5) return '';
  for (const k of NICK_KEYS) {
    const v = obj[k];
    if (typeof v === 'string') {
      const s = v.trim();
      // 跳过设备/平台口径的通用值，它们不是昵称
      if (s && s.length <= 32 && !/^(pc|windows|web|ide|trae|unknown)$/i.test(s)) return s;
    }
  }
  for (const v of Object.values(obj)) {
    if (v && typeof v === 'object') {
      const r = pickNickname(v, depth + 1);
      if (r) return r;
    }
  }
  return '';
}

/** 令牌是 JWT 时，载荷里常常带昵称；只取来当备注，不校验签名 */
function nicknameFromJwt(tok) {
  const parts = String(tok || '').split('.');
  if (parts.length < 3) return '';
  try {
    return pickNickname(JSON.parse(dec.decode(b64urlDecode(parts[1]))));
  } catch {
    return '';
  }
}

function describeExchangeErr(json, text, status) {
  const err = json?.ResponseMetadata?.Error || json?.error || {};
  const code = err.Code ?? json?.code;
  const msg =
    (err.Data && err.Data['__Message.error']) ||
    err.Message ||
    json?.message ||
    json?.msg ||
    String(text || '').slice(0, 160);
  return `code=${code ?? '?'} ${msg} (HTTP ${status})`;
}

/**
 * AuthCode → 双令牌。后端有几套不同版本的兑换端点，按下面顺序逐个尝试：
 *   主端点 DeviceInfo → 备用端点 AuthCode → 备用端点 Code
 * 这几步都不需要设备私钥，只要设备公钥已登记。
 */
async function exchangeAuthCode({ authCode, verifier, device, clientId, platform, host }) {
  const dev = {
    DeviceID: String(device.deviceId || ''),
    MachineID: String(device.machineId || ''),
    PlatformCode: platform,
    DeviceType: 'PC',
    DeviceName: 'PC',
    DeviceModel: '',
    ClientVersion: OAUTH_APP_VERSION,
    DevicePublicKey: String(device.publicKeyPem || ''),
    DeviceBrand: '',
    DeviceCPU: '',
    OSInfo: 'Windows',
    OSVersion: '10.0.19045',
  };

  const baseHeaders = {
    Accept: '*/*',
    'User-Agent': 'Trae/' + OAUTH_APP_VERSION,
    'x-device-id': dev.DeviceID,
    'x-app-id': OAUTH_APP_ID,
    'x-platform-code': platform,
  };

  const variants = [
    {
      tag: 'DeviceInfo',
      url: hostBase(host) + EP.exchange,
      headers: { ...baseHeaders, 'x-cloudide-token': '' },
      body: {
        ClientID: clientId,
        AuthCode: authCode,
        CodeVerifier: verifier,
        DeviceInfo: dev,
        IDEVersion: OAUTH_APP_VERSION,
      },
    },
    {
      tag: 'AuthCode',
      url: EP.exchangeLegacy,
      headers: baseHeaders,
      body: {
        ClientID: clientId,
        AuthCode: authCode,
        CodeVerifier: verifier,
        DeviceID: dev.DeviceID,
        PlatformCode: platform,
      },
    },
    {
      tag: 'Code',
      url: EP.exchangeLegacy,
      headers: baseHeaders,
      body: {
        ClientID: clientId,
        Code: authCode,
        CodeVerifier: verifier,
        DeviceID: dev.DeviceID,
        PlatformCode: platform,
      },
    },
  ];

  const errors = [];
  for (const v of variants) {
    const { status, json, text } = await traeFetch(v.url, {
      method: 'POST',
      headers: v.headers,
      body: JSON.stringify(v.body),
    });
    const refreshToken = deepFind(json, REFRESH_KEYS);
    const accessToken = deepFind(json, ACCESS_KEYS);
    if (refreshToken) {
      // 兑换响应偶尔带用户资料，能拿到昵称就直接当备注
      return { tokens: { refreshToken, accessToken }, tag: v.tag, name: pickNickname(json) || nicknameFromJwt(accessToken) };
    }
    if (accessToken) {
      errors.push(`${v.tag}: 响应只有 AccessToken，没有 RefreshToken（无法续期）${describeExchangeErr(json, text, status)}`);
    } else {
      errors.push(`${v.tag}: ${describeExchangeErr(json, text, status)}`);
    }
  }
  throw new Error('登录失败 → ' + errors.join(' | '));
}

const loginKey = (trace) => `login:${trace}`;

async function putLoginSession(env, sess) {
  await env.TRAE_KV.put(loginKey(sess.trace), await sealRecord(env, sess), { expirationTtl: LOGIN_TTL });
  await env.TRAE_KV.put(LOGIN_LATEST, sess.trace, { expirationTtl: LOGIN_TTL });
}

async function getLoginSession(env, trace) {
  const raw = await env.TRAE_KV.get(loginKey(trace));
  if (!raw) return null;
  try {
    return await openRecord(env, raw);
  } catch {
    return null;
  }
}

/** 把扫码换到的令牌落成账号（设备密钥随账号一起加密保存，供续期签名） */
async function saveScannedAccount(env, { label, refreshToken, device, clientId, platform }) {
  const rt = String(refreshToken || '').trim();
  if (!rt) throw new Error('登录响应里没有 refreshToken');

  const id = randomId(9);
  const acct = {
    id,
    label: String(label || '').trim().slice(0, 40) || `Trae-${String(device.deviceId || '').slice(-4)}`,
    refreshToken: rt,
    deviceId: String(device.deviceId || ''),
    machineId: String(device.machineId || ''),
    privateKeyPem: String(device.privateKeyPem || ''),
    publicKeyPem: String(device.publicKeyPem || ''),
    deviceName: 'PC',
    deviceModel: '',
    deviceBrand: '',
    deviceType: 'Windows',
    osInfo: 'Windows',
    osVersion: '10.0.19045',
    clientId: String(clientId || ''),
    platformCode: String(platform || ''),
    source: 'scan',
    createdAt: Date.now(),
    lastState: 'new',
    lastMsg: '扫码登录，尚未运行',
    cooldownUntil: 0,
  };
  await putAccount(env, acct);

  const list = await listAccounts(env);
  list.push({ id, label: acct.label, createdAt: acct.createdAt });
  await saveIndex(env, list);
  return acct;
}

/** 回调参数解析：AuthCode 可能在 authCodeInfo JSON 里，也可能直接是 code */
function parseCallbackParams(url) {
  const q = url.searchParams;
  let authCode = '';
  const raw = q.get('authCodeInfo');
  if (raw) {
    try {
      authCode = String(JSON.parse(raw).AuthCode || '').trim();
    } catch {
      /* 不是 JSON 就继续找 code */
    }
  }
  if (!authCode) authCode = String(q.get('code') || q.get('AuthCode') || '').trim();

  let refreshToken = '';
  for (const k of ['refreshToken', 'refresh_token', 'RefreshToken']) {
    const v = String(q.get(k) || '').trim().replace(/^"+|"+$/g, '');
    if (v) {
      refreshToken = v;
      break;
    }
  }

  return {
    authCode,
    refreshToken,
    trace: String(q.get('loginTraceID') || q.get('login_trace_id') || q.get('state') || '').trim(),
    host: String(q.get('host') || '').trim(),
    name: String(q.get('name') || q.get('nickname') || q.get('userName') || '').trim(),
    uid: String(q.get('uid') || '').trim(),
    error: String(q.get('error') || '').trim(),
  };
}

/** 完成一次登录：换取令牌 → 落库 → 回写会话状态 */
async function completeLogin(env, sess, p) {
  if (sess.status === 'ok') return { ok: true, label: sess.label, id: sess.accountId, repeat: true };

  let refreshToken = p.refreshToken;
  let via = 'callback';
  // 昵称来源：回调参数 → 令牌载荷 → 兑换响应，取到第一个算数
  let nick = p.name || nicknameFromJwt(p.refreshToken);
  if (!refreshToken) {
    if (!p.authCode) throw new Error('回调里既没有 AuthCode 也没有 refreshToken');
    const r = await exchangeAuthCode({
      authCode: p.authCode,
      verifier: sess.verifier,
      device: sess,
      clientId: sess.clientId,
      platform: sess.platform,
      host: p.host,
    });
    refreshToken = r.tokens.refreshToken;
    via = r.tag;
    nick = nick || r.name;
  }

  // 都拿不到就回落到设备后缀，用户可在控制台点「备注」自己改
  const label = String(nick || p.uid || '').trim() || `Trae-${String(sess.deviceId || '').slice(-4)}`;
  const acct = await saveScannedAccount(env, {
    label,
    refreshToken,
    device: sess,
    clientId: sess.clientId,
    platform: sess.platform,
  });

  sess.status = 'ok';
  sess.label = acct.label;
  sess.accountId = acct.id;
  sess.via = via;
  sess.error = '';
  await putLoginSession(env, sess);
  return { ok: true, label: acct.label, id: acct.id, via };
}

function escHtml(s) {
  return String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

/** 回调落地页：同源窗口可 postMessage 通知控制台，然后自动关窗 */
function oauthPage(title, detail, ok, label = '') {
  const payload = JSON.stringify({ type: 'trae-login', ok: !!ok, label: String(label || '') }).replace(/</g, '\\u003c');
  const color = ok ? '#0d8a61' : '#bf3529';
  const bg = ok ? 'rgba(13,138,97,.10)' : 'rgba(191,53,41,.10)';
  const icon = ok
    ? '<path d="M4.5 12.6l4.6 4.6L19.5 6.8"/>'
    : '<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>';
  const html =
    '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1"><title>' + escHtml(title) + '</title>' +
    '<style>*{box-sizing:border-box}body{margin:0;min-height:100dvh;display:grid;place-items:center;' +
    'font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;' +
    'background:#eef1f5;color:#0c141d;padding:24px}' +
    '.c{width:min(420px,92vw);background:#fff;border:1px solid rgba(15,23,42,.09);border-radius:18px;' +
    'padding:28px;text-align:center;box-shadow:0 18px 44px -24px rgba(15,23,42,.35)}' +
    '.m{width:52px;height:52px;margin:0 auto 16px;border-radius:16px;display:grid;place-items:center;' +
    'background:' + bg + '}.m svg{width:26px;height:26px;fill:none;stroke:' + color + ';stroke-width:2.6;' +
    'stroke-linecap:round;stroke-linejoin:round}h1{font-size:19px;margin:0 0 8px;letter-spacing:-.01em}' +
    'p{margin:0;color:#5e6a78;font-size:13.5px;word-break:break-word}' +
    '.tip{margin-top:18px;font-size:12px;color:#8b98a7}</style></head><body>' +
    '<div class="c"><div class="m"><svg viewBox="0 0 24 24">' + icon + '</svg></div>' +
    '<h1>' + escHtml(title) + '</h1><p>' + escHtml(detail) + '</p>' +
    '<div class="tip">' + (ok ? '窗口将自动关闭' : '可以关闭此窗口，回到控制台重试') + '</div></div>' +
    '<script>try{if(window.opener)window.opener.postMessage(' + payload + ",'*')}catch(e){}" +
    (ok ? 'setTimeout(function(){try{window.close()}catch(e){}},1400);' : '') +
    '</' + 'script></body></html>';
  return new Response(html, {
    status: ok ? 200 : 400,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

/** 第一步：生成设备身份 + PKCE + 授权链接 */
async function handleLoginStart(request, env) {
  const callback = CALLBACK_LOCAL;

  const device = await genDeviceIdentity();
  const deviceId = genDeviceId();
  const machineId = randomHex(16);
  const { verifier, challenge } = await pkcePair();
  const trace = randomHex(8);

  const authUrl = buildAuthorizeUrl({
    authFrom: TRAE_LINE.authFrom,
    clientId: TRAE_LINE.clientId,
    trace,
    callback,
    deviceId,
    machineId,
    challenge,
  });

  const sess = {
    trace,
    line: 'trae',
    verifier,
    callback,
    deviceId,
    machineId,
    privateKeyPem: device.privateKeyPem,
    publicKeyPem: device.publicKeyPem,
    clientId: TRAE_LINE.clientId,
    platform: TRAE_LINE.platform,
    status: 'pending',
    createdAt: Date.now(),
  };
  await putLoginSession(env, sess);

  return json({
    ok: true,
    trace,
    authUrl,
    callback,
    deviceId,
    line: 'trae',
    label: TRAE_LINE.label,
  });
}

/** 第二步（自动）：官网把浏览器送到这里，带 AuthCode */
async function handleOauthCallback(request, env) {
  const url = new URL(request.url);
  const p = parseCallbackParams(url);

  // 无凭据也无 trace：多半是官网在探测「客户端是否在线」，直接 200 即可
  if (!p.authCode && !p.refreshToken && !p.error && !p.trace) {
    return new Response('ok', { headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' } });
  }

  if (p.error) return oauthPage('授权未完成', p.error, false);

  let trace = p.trace;
  if (!trace) trace = String((await env.TRAE_KV.get(LOGIN_LATEST)) || '');
  if (!trace) return oauthPage('登录会话丢失', '找不到对应的登录会话，请回到控制台重新发起', false);

  const sess = await getLoginSession(env, trace);
  if (!sess) return oauthPage('登录会话已过期', '二维码有效期 15 分钟，请回到控制台重新获取', false);

  try {
    const r = await completeLogin(env, sess, p);
    return oauthPage(r.repeat ? '这个二维码已经用过了' : '登录成功', `已保存为「${r.label}」`, true, r.label);
  } catch (e) {
    sess.status = 'error';
    sess.error = e.message;
    await putLoginSession(env, sess);
    return oauthPage('换取令牌失败', e.message, false);
  }
}

/** 轮询：控制台查这次扫码有没有完成 */
async function handleLoginPoll(request, env) {
  const url = new URL(request.url);
  const trace = String(url.searchParams.get('trace') || '').trim();
  if (!trace) return json({ error: '缺少 trace' }, 400);
  const sess = await getLoginSession(env, trace);
  if (!sess) return json({ status: 'expired' });
  return json({
    status: sess.status || 'pending',
    label: sess.label || '',
    error: sess.error || '',
    accountId: sess.accountId || '',
    via: sess.via || '',
  });
}

/**
 * 第二步：官网只把 AuthCode 回送到 127.0.0.1，用户把那段地址粘回来，
 * 这里解析出 AuthCode 后换取令牌并绑定账号。
 */
async function handleLoginClaim(request, env) {
  const body = await readBody(request);
  const text = String(body.url || body.text || '').trim();
  if (!text) return json({ error: '请粘贴回调地址' }, 400);

  let u;
  try {
    u = new URL(text);
  } catch {
    try {
      const tail = text.startsWith('?') ? text : text.replace(/^[?/]+/, '');
      u = new URL('https://placeholder.local/' + tail);
    } catch {
      return json({ error: '这不像是回调地址' }, 400);
    }
  }

  const p = parseCallbackParams(u);
  if (!p.authCode && !p.refreshToken) {
    return json({ error: '地址里没找到 authCodeInfo / code，请复制完整地址（含 ? 之后的部分）' }, 400);
  }

  let trace = p.trace || String((await env.TRAE_KV.get(LOGIN_LATEST)) || '');
  if (!trace) return json({ error: '没有待完成的登录会话，请先点「添加账号」' }, 400);

  const sess = await getLoginSession(env, trace);
  if (!sess) return json({ error: '登录会话已过期，请重新发起' }, 400);

  try {
    const r = await completeLogin(env, sess, p);
    return json({ ok: true, label: r.label, id: r.id, via: r.via });
  } catch (e) {
    sess.status = 'error';
    sess.error = e.message;
    await putLoginSession(env, sess);
    return json({ error: e.message }, 502);
  }
}

const PAGE = '<!DOCTYPE html><meta charset="utf-8"><title>控制台</title><p>控制台在根路径 <a href="/">/</a>。</p>';

/* ------------------------------------------------------------------ */
/* 入口                                                                */
/* ------------------------------------------------------------------ */

const __mod = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const method = request.method.toUpperCase();

    try {
      if (path === '/' || path === '/index.html') {
        return new Response(PAGE, {
          headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
        });
      }

      // 定时任务入口：口令走 header/query，不需要登录密码
      if (path === '/cron') {
        const c = requireCron(request, env);
        if (!c.ok) return c.res;
        return handleRun(request, env, false);
      }

      // 扫码登录回调：由浏览器跳转过来，带不了 admin token，只能靠 state 校验
      if (path === '/oauth/callback' && method === 'GET') return handleOauthCallback(request, env);
      if (path === '/oauth/probe' && (method === 'GET' || method === 'HEAD')) {
        return new Response('ok', { headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' } });
      }

      if (!path.startsWith('/api/')) return json({ error: 'not found' }, 404);

      const a = requireAdmin(request, env);
      if (!a.ok) return a.res;

      if (path === '/api/login/start' && method === 'POST') return handleLoginStart(request, env);
      if (path === '/api/login/poll' && method === 'GET') return handleLoginPoll(request, env);
      if (path === '/api/login/claim' && method === 'POST') return handleLoginClaim(request, env);

      if (path === '/api/list' && method === 'GET') return handleList(request, env);
      if (path === '/api/accounts/remove' && method === 'POST') return handleRemove(request, env);
      if (path === '/api/rename' && method === 'POST') return handleRename(request, env);
      if (path === '/api/run' && method === 'POST') {
        const force = url.searchParams.get('force') === '1';
        return handleRun(request, env, force);
      }

      return json({ error: 'not found' }, 404);
    } catch (e) {
      return json({ error: e.message || String(e) }, 500);
    }
  },

  /** Cloudflare Cron Trigger 到点自动跑 */
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      (async () => {
        const list = await listAccounts(env);
        for (const meta of list) {
          const acct = await getAccount(env, meta.id);
          if (!acct) continue;
          try {
            await signinOne(env, acct, { force: false });
          } catch {
            /* 单账号失败不影响其他账号 */
          }
        }
      })()
    );
  },
};

/** 内部函数，供自检代码验证签名流程，不参与运行时逻辑 */
const __internal = { ecSign, importPrivateKey, derSig, jwtExp, buildProof, PEM_TEST: true };


return { fetch: __mod.fetch, scheduled: __mod.scheduled, __internal };
})();


/* ================================================================== */
/* 模块二：WorkBuddy —— 扫码授权 / 令牌续期 / 签到 */
/* ================================================================== */

const WorkBuddy = (() => {
const API = 'https://copilot.tencent.com';

/* ------------------------------------------------------------------ */
/* 编码工具                                                            */
/* ------------------------------------------------------------------ */

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64encode(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function b64decode(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlEncode(buf) {
  return b64encode(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const s = str.replace(/-/g, '+').replace(/_/g, '/');
  return b64decode(s + '='.repeat((4 - (s.length % 4)) % 4));
}

function randomId(bytes = 12) {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** 定长比较，避免口令被时序侧信道猜出来 */
function timingSafeEqual(a, b) {
  const x = enc.encode(String(a ?? ''));
  const y = enc.encode(String(b ?? ''));
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

/* ------------------------------------------------------------------ */
/* 加密：AES-256-GCM + 每条记录随机 salt，密钥由主密钥 HKDF 派生        */
/* ------------------------------------------------------------------ */

async function deriveKey(env, salt) {
  const raw = env.WB_MASTER_KEY;
  if (!raw) throw new Error('缺少 MASTER_KEY');

  let master;
  try {
    master = b64decode(raw.trim());
  } catch {
    throw new Error('MASTER_KEY 不是合法 base64');
  }
  if (master.length !== 32) throw new Error('MASTER_KEY 必须是 32 字节（base64 后 44 字符）');

  const base = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('wb-signin/v1/account') },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function sealRecord(env, obj) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(env, salt);
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    enc.encode(JSON.stringify(obj))
  );
  return JSON.stringify({ v: 1, s: b64encode(salt), i: b64encode(iv), d: b64encode(ct) });
}

async function openRecord(env, text) {
  const box = JSON.parse(text);
  if (box.v !== 1) throw new Error('不认识的记录版本');
  const key = await deriveKey(env, b64decode(box.s));
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64decode(box.i) },
    key,
    b64decode(box.d)
  );
  return JSON.parse(dec.decode(pt));
}

/* ------------------------------------------------------------------ */
/* KV 读写                                                             */
/* ------------------------------------------------------------------ */

const acctKey = (id) => `acct:${id}`;
const INDEX_KEY = 'index:accounts';

async function listAccounts(env) {
  const raw = await env.WB_KV.get(INDEX_KEY);
  return raw ? JSON.parse(raw) : [];
}

async function saveIndex(env, list) {
  await env.WB_KV.put(INDEX_KEY, JSON.stringify(list));
}

async function getAccount(env, id) {
  const raw = await env.WB_KV.get(acctKey(id));
  if (!raw) return null;
  return openRecord(env, raw);
}

async function putAccount(env, acct) {
  await env.WB_KV.put(acctKey(acct.id), await sealRecord(env, acct));
}

/* ------------------------------------------------------------------ */
/* 与 WorkBuddy 服务端交互                                              */
/* ------------------------------------------------------------------ */

async function wbFetch(path, { method = 'POST', headers = {}, body = '{}', timeout = 20000 } = {}) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(API + path, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'workbuddy-signin-worker/1.0',
        ...headers,
      },
      body: method === 'GET' ? undefined : body,
      signal: ctrl.signal,
    });
    const text = await res.text();
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      throw new Error(`响应不是 JSON (HTTP ${res.status}): ${text.slice(0, 120)}`);
    }
    return { status: res.status, json };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * 用 refresh_token 换新的双令牌。
 * 注意：refreshToken 会轮换，先前签发的随即失效，调用方必须立刻保存新的。
 */
async function refreshTokens(refreshToken) {
  const { status, json } = await wbFetch('/v2/plugin/auth/token/refresh', {
    headers: {
      'X-Refresh-Token': refreshToken,
      'X-Auth-Refresh-Source': 'plugin',
      'X-Domain': 'copilot.tencent.com',
    },
  });

  if (json?.code !== 0 || !json?.data) {
    const err = new Error(
      `刷新令牌失败 code=${json?.code} ${json?.msg ?? ''} (HTTP ${status})`
    );
    err.code = json?.code;
    err.fatal = true; // 令牌链路断了，需要人工重新抓
    throw err;
  }

  const d = json.data;
  return {
    accessToken: d.accessToken,
    refreshToken: d.refreshToken || refreshToken,
    expiresIn: Number(d.expiresIn) || 0,
    refreshExpiresIn: Number(d.refreshExpiresIn) || 0,
  };
}

/**
 * 扫码登录第一步：向服务端申请一个登录态。
 * 返回的 authUrl 就是官方登录页（微信扫码页），state 用来轮询结果。
 */
async function requestLoginState() {
  const { status, json } = await wbFetch('/v2/plugin/auth/state?platform=workbuddy', {
    headers: {
      'X-No-Authorization': 'true',
      'X-No-User-Id': 'true',
      'X-No-Enterprise-Id': 'true',
      'X-No-Department-Info': 'true',
      'X-Domain': 'copilot.tencent.com',
    },
  });
  if (json?.code !== 0 || !json?.data?.state) {
    throw new Error(`申请登录态失败 code=${json?.code} ${json?.msg ?? ''} (HTTP ${status})`);
  }
  return { state: json.data.state, authUrl: json.data.authUrl };
}

/**
 * 扫码登录第二步：轮询这个 state 有没有被授权。
 *   code 11217 → 还在等扫码/确认
 *   code 0     → 已经拿到令牌
 */
async function pollLoginToken(state) {
  const { status, json } = await wbFetch(
    `/v2/plugin/auth/token?state=${encodeURIComponent(state)}`,
    {
      method: 'GET',
      headers: {
        'X-No-Authorization': 'true',
        'X-No-User-Id': 'true',
        'X-No-Enterprise-Id': 'true',
        'X-No-Department-Info': 'true',
        'X-Domain': 'copilot.tencent.com',
      },
    }
  );
  if (json?.code === 11217) return { pending: true };
  if (json?.code === 0 && json?.data?.accessToken) return { tokens: json.data };
  throw new Error(`轮询登录结果失败 code=${json?.code} ${json?.msg ?? ''} (HTTP ${status})`);
}

/** 尽量取一个昵称当备注名，取不到就算了，不影响登录 */
async function fetchNickname(at) {
  try {
    const { json } = await wbFetch('/v2/accounts', {
      method: 'GET',
      headers: { ...authHeader(at), 'X-Domain': 'copilot.tencent.com' },
    });
    const list = json?.data?.accounts ?? json?.data;
    const first = Array.isArray(list) ? list[0] : null;
    return String(first?.nickname ?? first?.nickName ?? '').trim();
  } catch {
    return '';
  }
}

/** 把一条令牌落成账号记录（加密存 KV + 更新索引） */
async function persistAccount(env, { refreshToken, label, accessToken }) {
  const id = randomId(9);
  let name = String(label ?? '').trim().slice(0, 40);
  if (!name && accessToken) name = await fetchNickname(accessToken);
  if (!name) name = `账号-${id.slice(0, 4)}`;

  const acct = {
    id,
    label: name,
    refreshToken,
    createdAt: Date.now(),
    lastState: 'new',
    lastMsg: '尚未运行',
    verified: true,
    tokenRefreshedAt: Date.now(),
  };
  await putAccount(env, acct);

  const list = await listAccounts(env);
  list.push({ id, label: acct.label, createdAt: acct.createdAt });
  await saveIndex(env, list);
  return acct;
}

const authHeader = (at) => ({ Authorization: `Bearer ${at}` });

async function checkinStatus(at) {
  const { json } = await wbFetch('/v2/billing/meter/checkin-activity-status', {
    headers: authHeader(at),
  });
  if (json?.code !== 0 || !json?.data) {
    return { ok: false, code: json?.code, msg: json?.msg };
  }
  return { ok: true, data: json.data };
}

async function doCheckin(at) {
  const { json } = await wbFetch('/v2/billing/meter/daily-checkin', {
    headers: authHeader(at),
  });
  if (json?.code === 0) {
    return { state: 'checked', credit: json.data?.credit ?? 100, raw: json.data };
  }
  if (json?.code === 10001) {
    return { state: 'already', credit: 0 };
  }
  return { state: 'error', code: json?.code, msg: json?.msg };
}

/* ------------------------------------------------------------------ */
/* 单个账号的完整签到流程                                               */
/* ------------------------------------------------------------------ */

async function signinOne(env, acct, { force = false } = {}) {
  const now = Date.now();
  const today = new Date(now + 8 * 3600 * 1000).toISOString().slice(0, 10); // 按北京时间算日期

  // 今天已成功过、且没要求强制，直接跳过（省一次请求，也避免无谓刷新）
  if (!force && acct.lastOkDate === today && acct.lastState !== 'error') {
    return { id: acct.id, label: acct.label, state: 'skipped', msg: '今日已完成' };
  }

  let tokens;
  try {
    tokens = await refreshTokens(acct.refreshToken);
  } catch (e) {
    acct.lastState = e.fatal ? 'token_dead' : 'error';
    acct.lastMsg = e.message;
    acct.lastRun = now;
    await putAccount(env, acct);
    return { id: acct.id, label: acct.label, state: acct.lastState, msg: e.message };
  }

  // 先落盘新令牌。哪怕后面签到失败，令牌链也不能断。
  acct.refreshToken = tokens.refreshToken;
  acct.tokenRefreshedAt = now;

  let result;
  try {
    result = await doCheckin(tokens.accessToken);
  } catch (e) {
    acct.lastState = 'error';
    acct.lastMsg = `签到请求异常: ${e.message}`;
    acct.lastRun = now;
    await putAccount(env, acct);
    return { id: acct.id, label: acct.label, state: 'error', msg: acct.lastMsg };
  }

  let streak = null;
  let total = null;
  try {
    const st = await checkinStatus(tokens.accessToken);
    if (st.ok) {
      streak = st.data.streak_days ?? null;
      total = st.data.total_credits ?? null;
      // 顺手把最新 accessToken 的服务端视图对上，用于判断是否真的已签
      if (st.data.checked_in_today === true && result.state === 'error') {
        result = { state: 'already', credit: 0 };
      }
    }
  } catch {
    /* 状态查询失败不影响主流程 */
  }

  acct.lastRun = now;
  acct.streak = streak;
  acct.total = total;

  if (result.state === 'error') {
    acct.lastState = 'error';
    acct.lastMsg = `签到失败 code=${result.code} ${result.msg ?? ''}`;
  } else {
    acct.lastState = result.state; // 'checked' | 'already'
    acct.lastMsg = result.state === 'checked' ? `+${result.credit} 积分` : '今日已签';
    acct.lastOkDate = today;
    if (result.state === 'checked') {
      acct.lastCredit = result.credit;
      acct.totalSigned = (acct.totalSigned ?? 0) + 1;
    }
  }

  await putAccount(env, acct);
  return {
    id: acct.id,
    label: acct.label,
    state: acct.lastState,
    msg: acct.lastMsg,
    streak,
    total,
  };
}

/* ------------------------------------------------------------------ */
/* 页面与鉴权辅助                                                       */
/* ------------------------------------------------------------------ */

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

function requireAdmin(request, env) {
  const url = new URL(request.url);
  const given =
    request.headers.get('X-Admin-Token') ||
    (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '') ||
    url.searchParams.get('token');
  if (!env.ADMIN_TOKEN) return { ok: false, res: json({ error: '未配置 ADMIN_TOKEN' }, 500) };
  if (!timingSafeEqual(given, env.ADMIN_TOKEN)) {
    return { ok: false, res: json({ error: '登录密码不正确' }, 401) };
  }
  return { ok: true };
}

function requireCron(request, env) {
  const secret = env.CRON_SECRET || env.ADMIN_TOKEN;
  const url = new URL(request.url);
  const given = request.headers.get('X-Cron-Secret') || url.searchParams.get('key');
  if (!secret) return { ok: false, res: json({ error: '未配置 CRON_SECRET / ADMIN_TOKEN' }, 500) };
  if (!timingSafeEqual(given, secret)) return { ok: false, res: json({ error: '口令不对' }, 401) };
  return { ok: true };
}

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

/* ------------------------------------------------------------------ */
/* 路由                                                                */
/* ------------------------------------------------------------------ */

/** 扫码登录：申请二维码（其实是一个官方登录页地址） */
async function handleLoginStart(request, env) {
  const { state, authUrl } = await requestLoginState();
  // 记一下 state 是我们发出去的，避免有人拿别人的 state 来轮询
  await env.WB_KV.put(`login:${state}`, String(Date.now()), { expirationTtl: 900 });
  return json({ ok: true, state, authUrl });
}

/** 扫码登录：轮询授权结果，拿到令牌就顺手存成账号 */
async function handleLoginPoll(request, env) {
  const url = new URL(request.url);
  const state = String(url.searchParams.get('state') ?? '').trim();
  if (!state) return json({ error: '缺少 state' }, 400);

  const known = await env.WB_KV.get(`login:${state}`);
  if (!known) return json({ error: '登录会话已过期，请重新获取二维码' }, 400);

  const r = await pollLoginToken(state);
  if (r.pending) return json({ status: 'pending' });

  const rt = String(r.tokens.refreshToken ?? '').trim();
  if (!rt) return json({ error: '登录成功但服务端没返回 refreshToken' }, 502);

  const acct = await persistAccount(env, { refreshToken: rt, accessToken: r.tokens.accessToken });
  await env.WB_KV.delete(`login:${state}`);
  return json({ status: 'ok', id: acct.id, label: acct.label });
}

async function handleList(request, env) {
  const list = await listAccounts(env);
  const out = [];
  for (const meta of list) {
    const a = await getAccount(env, meta.id);
    if (!a) continue;
    out.push({
      id: a.id,
      label: a.label,
      lastState: a.lastState,
      lastMsg: a.lastMsg,
      lastRun: a.lastRun ? new Date(a.lastRun + 8 * 3600e3).toISOString().replace('Z', ' +08:00') : null,
      lastOkDate: a.lastOkDate ?? null,
      streak: a.streak ?? null,
      total: a.total ?? null,
      totalSigned: a.totalSigned ?? 0,
      // 永远不返回令牌，连指纹都不给
    });
  }
  return json({ count: out.length, accounts: out });
}

async function handleRemove(request, env) {
  const body = await readBody(request);
  const id = String(body.id ?? '').trim();
  if (!id) return json({ error: '缺少 id' }, 400);
  await env.WB_KV.delete(acctKey(id));
  const list = (await listAccounts(env)).filter((x) => x.id !== id);
  await saveIndex(env, list);
  return json({ ok: true, removed: id });
}

/** 改备注：登录时取不到昵称的账号，允许手动命名 */
async function handleRename(request, env) {
  const body = await readBody(request);
  const id = String(body.id ?? '').trim();
  const label = String(body.label ?? '').trim().slice(0, 40);
  if (!id) return json({ error: '缺少 id' }, 400);
  if (!label) return json({ error: '备注不能为空' }, 400);

  const acct = await getAccount(env, id);
  if (!acct) return json({ error: '账号不存在' }, 404);
  acct.label = label;
  await putAccount(env, acct);

  const list = await listAccounts(env);
  await saveIndex(env, list.map((x) => (x.id === id ? { ...x, label } : x)));
  return json({ ok: true, id, label });
}

async function handleRun(request, env, force) {
  const list = await listAccounts(env);
  const results = [];
  for (const meta of list) {
    const a = await getAccount(env, meta.id);
    if (!a) continue;
    try {
      results.push(await signinOne(env, a, { force }));
    } catch (e) {
      results.push({ id: a.id, label: a.label, state: 'error', msg: e.message });
    }
  }
  const summary = {
    at: new Date(Date.now() + 8 * 3600e3).toISOString().replace('Z', ' +08:00'),
    accounts: results.length,
    checked: results.filter((r) => r.state === 'checked').length,
    already: results.filter((r) => r.state === 'already' || r.state === 'skipped').length,
    failed: results.filter((r) => r.state === 'error' || r.state === 'token_dead').length,
    results,
  };
  return json(summary);
}

const PAGE = '<!DOCTYPE html><meta charset="utf-8"><title>控制台</title><p>控制台在根路径 <a href="/">/</a>。</p>';

/* ------------------------------------------------------------------ */
/* 入口                                                                */
/* ------------------------------------------------------------------ */

const __mod = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const method = request.method.toUpperCase();

    try {
      if (path === '/' || path === '/index.html') {
        return new Response(PAGE, {
          headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
        });
      }

      // 定时任务入口：口令走 header/query，不需要登录密码
      if (path === '/cron') {
        const c = requireCron(request, env);
        if (!c.ok) return c.res;
        return handleRun(request, env, false);
      }

      if (!path.startsWith('/api/')) return json({ error: 'not found' }, 404);

      const a = requireAdmin(request, env);
      if (!a.ok) return a.res;

      if (path === '/api/list' && method === 'GET') return handleList(request, env);
      if (path === '/api/login/start' && method === 'POST') return handleLoginStart(request, env);
      if (path === '/api/login/poll' && method === 'GET') return handleLoginPoll(request, env);
      if (path === '/api/remove' && method === 'POST') return handleRemove(request, env);
      if (path === '/api/rename' && method === 'POST') return handleRename(request, env);
      if (path === '/api/run' && method === 'POST') {
        const force = url.searchParams.get('force') === '1';
        return handleRun(request, env, force);
      }

      return json({ error: 'not found' }, 404);
    } catch (e) {
      return json({ error: e.message || String(e) }, 500);
    }
  },

  /** Cloudflare Cron Trigger 到点自动跑 */
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      (async () => {
        const list = await listAccounts(env);
        for (const meta of list) {
          const acct = await getAccount(env, meta.id);
          if (!acct) continue;
          try {
            await signinOne(env, acct, { force: false });
          } catch {
            /* 单账号失败不影响其他账号 */
          }
        }
      })()
    );
  },
};


return { fetch: __mod.fetch, scheduled: __mod.scheduled };
})();


/* ================================================================== */
/* 模块三：外壳 —— 绑定适配 / 路由分发 / 控制台 */
/* ================================================================== */

/* ------------------------------------------------------------------ */
/* 外壳                                                                */
/*                                                                     */
/* 只做三件事：                                                        */
/*   1. 把共享绑定翻译成两个模块各自认识的 env（KV 按前缀隔离）          */
/*   2. 按路径前缀把请求分发给对应模块                                  */
/*   3. 渲染控制台页面，并提供跨平台的汇总与批量签到                    */
/* ------------------------------------------------------------------ */

/* ---------------- 绑定适配 ---------------- */

/** 把共享 KV 包装成带前缀的视图，两个平台互不越界 */
function kvScope(kv, prefix) {
  const strip = (keys) => (keys || []).map((x) => ({ ...x, name: String(x.name).slice(prefix.length) }));
  return {
    async get(k, o) {
      return kv.get(prefix + k, o);
    },
    async put(k, v, o) {
      return kv.put(prefix + k, v, o);
    },
    async delete(k) {
      return kv.delete(prefix + k);
    },
    async list(o = {}) {
      const r = await kv.list({ ...o, prefix: prefix + (o.prefix || '') });
      return { ...r, keys: strip(r.keys) };
    },
  };
}

/** 没绑 KV 时给出一个会说话的桩，而不是 undefined 引发的 TypeError */
function missingKV(hint) {
  const boom = () => {
    throw new Error(hint);
  };
  return { get: boom, put: boom, delete: boom, list: boom };
}

function kvFor(env, prefix) {
  if (env.KV) return kvScope(env.KV, prefix);
  return missingKV('未绑定 KV：请给 Worker 添加一个 KV 命名空间，变量名填 KV');
}

function traeEnv(env) {
  return {
    TRAE_KV: kvFor(env, 'trae:'),
    TRAE_MASTER_KEY: env.MASTER_KEY,
    ADMIN_TOKEN: env.ADMIN_TOKEN,
    CRON_SECRET: env.CRON_SECRET,
  };
}

function wbEnv(env) {
  return {
    WB_KV: kvFor(env, 'wb:'),
    WB_MASTER_KEY: env.MASTER_KEY,
    ADMIN_TOKEN: env.ADMIN_TOKEN,
    CRON_SECRET: env.CRON_SECRET,
  };
}

/* ---------------- 通用响应与鉴权 ---------------- */

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

function htmlResponse(body, status = 200) {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

function safeEqual(a, b) {
  const x = new TextEncoder().encode(String(a ?? ''));
  const y = new TextEncoder().encode(String(b ?? ''));
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

function requireAdmin(request, env) {
  const url = new URL(request.url);
  const given =
    request.headers.get('X-Admin-Token') ||
    (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '') ||
    url.searchParams.get('token');
  if (!env.ADMIN_TOKEN) return { ok: false, res: json({ error: '未配置 ADMIN_TOKEN' }, 500) };
  if (!safeEqual(given, env.ADMIN_TOKEN)) return { ok: false, res: json({ error: '登录密码不正确' }, 401) };
  return { ok: true };
}

function requireCron(request, env) {
  const secret = env.CRON_SECRET || env.ADMIN_TOKEN;
  const url = new URL(request.url);
  const given = request.headers.get('X-Cron-Secret') || url.searchParams.get('key');
  if (!secret) return { ok: false, res: json({ error: '未配置 CRON_SECRET / ADMIN_TOKEN' }, 500) };
  if (!safeEqual(given, secret)) return { ok: false, res: json({ error: '口令不对' }, 401) };
  return { ok: true };
}

/** 子模块只认 request.url 上的 path，这里按前缀改写后转发 */
function repath(request, path) {
  const u = new URL(request.url);
  u.pathname = path || '/';
  return new Request(u.toString(), request);
}

/** 以内部请求的方式驱动某个平台的 /api/run，拿到它的汇总 */
async function runPlatform(mod, env, origin, force) {
  const target = new URL('/api/run' + (force ? '?force=1' : ''), origin);
  const req = new Request(target.toString(), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Admin-Token': String(env.ADMIN_TOKEN || '') },
    body: '{}',
  });
  const res = await mod.fetch(req, env, { waitUntil() {} });
  const data = await res.json().catch(() => ({ error: 'HTTP ' + res.status }));
  return data;
}

async function runAll(env, origin, force) {
  const out = {};
  for (const [key, mod, e] of [
    ['trae', Trae, traeEnv(env)],
    ['wb', WorkBuddy, wbEnv(env)],
  ]) {
    try {
      out[key] = await runPlatform(mod, e, origin, force);
    } catch (err) {
      out[key] = { error: err.message || String(err) };
    }
  }
  return {
    at: new Date(Date.now() + 8 * 3600e3).toISOString().replace('Z', ' +08:00'),
    ...out,
  };
}

/* ------------------------------------------------------------------ */
/* 控制台页面                                                          */
/* ------------------------------------------------------------------ */

const PAGE = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>签到控制台 · Trae + WorkBuddy</title>
<style>
  :root{
    --bg:#eef1f5;--glow-a:rgba(16,160,110,.11);--glow-b:rgba(56,110,220,.09);--grid:rgba(15,23,42,.035);
    --surface:#fff;--surface-2:#f6f8fa;--line:rgba(15,23,42,.09);--line-2:rgba(15,23,42,.16);
    --txt:#0c141d;--dim:#5e6a78;--pri:#0d8a61;--pri-ink:#fff;--ring:rgba(13,138,97,.16);
    --ok:#0d8a61;--ok-bg:rgba(13,138,97,.10);--warn:#9a6407;--warn-bg:rgba(190,124,15,.13);
    --bad:#bf3529;--bad-bg:rgba(191,53,41,.10);--idle:#5e6a78;--idle-bg:rgba(15,23,42,.055);
    --bar:rgba(238,241,245,.78);--sh-1:0 1px 2px rgba(15,23,42,.04),0 10px 26px -16px rgba(15,23,42,.22);
    --sh-2:0 18px 44px -22px rgba(15,23,42,.35);--r:16px;
    --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;
  }
  @media (prefers-color-scheme:dark){
    :root{
      --bg:#070a0e;--glow-a:rgba(45,208,126,.16);--glow-b:rgba(70,110,255,.13);--grid:rgba(255,255,255,.035);
      --surface:#101822;--surface-2:#0c131b;--line:rgba(255,255,255,.075);--line-2:rgba(255,255,255,.14);
      --txt:#e8eef5;--dim:#8b98a7;--pri:#2fd07e;--pri-ink:#04150d;--ring:rgba(47,208,126,.20);
      --ok:#3ddc97;--ok-bg:rgba(61,220,151,.13);--warn:#e6ae4a;--warn-bg:rgba(230,174,74,.13);
      --bad:#ff7d6e;--bad-bg:rgba(255,125,110,.13);--idle:#8b98a7;--idle-bg:rgba(255,255,255,.06);
      --bar:rgba(7,10,14,.72);--sh-1:0 1px 0 rgba(255,255,255,.03),0 14px 34px -22px rgba(0,0,0,.95);
      --sh-2:0 26px 60px -30px rgba(0,0,0,1);
    }
  }
  *{box-sizing:border-box}
  [hidden]{display:none!important}
  body{margin:0;background:var(--bg);color:var(--txt);-webkit-font-smoothing:antialiased;
       font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif}
  body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
    background:radial-gradient(58% 46% at 8% -6%,var(--glow-a),transparent 62%),
               radial-gradient(46% 42% at 96% 2%,var(--glow-b),transparent 62%)}
  body::after{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;background-image:
      linear-gradient(var(--grid) 1px,transparent 1px),linear-gradient(90deg,var(--grid) 1px,transparent 1px);
    background-size:46px 46px;
    -webkit-mask-image:radial-gradient(72% 58% at 50% 0%,#000,transparent 78%);
            mask-image:radial-gradient(72% 58% at 50% 0%,#000,transparent 78%)}
  .wrap{position:relative;z-index:1;max-width:1920px;margin:0 auto;
        padding:clamp(16px,2.6vw,36px) clamp(16px,3vw,44px) 68px}

  .brand{display:flex;align-items:center;gap:13px}
  .mark{width:44px;height:44px;flex:0 0 auto;border-radius:14px;display:grid;place-items:center;
        background:linear-gradient(155deg,var(--pri),#0a6a4a);
        box-shadow:var(--sh-2),inset 0 1px 0 rgba(255,255,255,.3)}
  .mark svg{width:21px;height:21px;fill:none;stroke:#fff;stroke-width:2.6;stroke-linecap:round;stroke-linejoin:round}
  .eyebrow{font-family:var(--mono);font-size:10px;letter-spacing:.18em;text-transform:uppercase;color:var(--dim)}
  h1{font-size:clamp(19px,2.6vw,23px);margin:1px 0 0;font-weight:700;letter-spacing:-.02em;line-height:1.25}

  #loginView{min-height:min(74dvh,640px);display:grid;place-content:center;gap:26px}
  .login-card{width:min(470px,92vw);padding:26px;background:var(--surface);border:1px solid var(--line);
              border-radius:var(--r);box-shadow:var(--sh-1)}
  .lbl{display:block;font-family:var(--mono);font-size:10.5px;letter-spacing:.14em;
       text-transform:uppercase;color:var(--dim);margin-bottom:9px}
  .field{display:flex;gap:10px}
  .field input{flex:1;min-width:0}

  input{font:inherit;padding:12px 14px;border:1px solid var(--line-2);border-radius:12px;
        background:var(--surface);color:var(--txt);outline:none;transition:border-color .18s,box-shadow .18s;width:100%}
  input::placeholder{color:var(--dim)}
  input:focus{border-color:var(--pri);box-shadow:0 0 0 4px var(--ring)}
  button{font:inherit;font-weight:600;display:inline-flex;align-items:center;justify-content:center;gap:8px;
         padding:11px 18px;border-radius:12px;border:1px solid var(--line-2);background:var(--surface);color:var(--txt);
         cursor:pointer;transition:transform .12s ease,box-shadow .18s ease,border-color .18s ease,filter .18s ease}
  button:hover{border-color:var(--txt);transform:translateY(-1px);box-shadow:var(--sh-1)}
  button:active{transform:none}
  button:focus-visible{outline:2px solid var(--pri);outline-offset:2px}
  button.pri{background:var(--pri);border-color:transparent;color:var(--pri-ink);
             box-shadow:inset 0 1px 0 rgba(255,255,255,.22),0 12px 26px -14px var(--pri)}
  button.pri:hover{border-color:transparent;filter:brightness(1.06)}
  button:disabled{opacity:.55;cursor:not-allowed;transform:none;box-shadow:none}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}

  .topbar{position:sticky;top:0;z-index:4;display:flex;align-items:center;justify-content:space-between;
          gap:14px;flex-wrap:wrap;padding:12px 0 14px;margin-bottom:14px;background:var(--bar);
          backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}
  .chip{display:inline-flex;align-items:center;gap:8px;padding:7px 13px;border-radius:999px;border:1px solid var(--line);
        background:var(--surface);font-size:12.5px;color:var(--dim);white-space:nowrap;box-shadow:var(--sh-1)}
  .chip b{color:var(--txt);font-family:var(--mono);font-variant-numeric:tabular-nums;font-size:12px}
  .chip .dot{width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 3px var(--ok-bg)}

  .tabs{display:flex;gap:4px;margin-bottom:18px;padding:4px;border:1px solid var(--line);border-radius:14px;
        background:var(--surface-2);width:fit-content;max-width:100%;overflow:auto}
  .tab{display:inline-flex;align-items:center;gap:9px;padding:10px 20px;border:0;border-radius:10px;background:transparent;
       color:var(--dim);font-size:14px;font-weight:600;white-space:nowrap;box-shadow:none}
  .tab:hover{color:var(--txt);background:var(--ok-bg);transform:none;box-shadow:none}
  .tab.on{background:var(--pri);color:var(--pri-ink);font-weight:700;box-shadow:0 6px 16px var(--ring)}
  .tab.on:hover{background:var(--pri);color:var(--pri-ink)}
  .tab b{font-family:var(--mono);font-size:11px;font-weight:600;padding:1px 7px;border-radius:999px;
         background:var(--idle-bg);color:var(--dim);font-variant-numeric:tabular-nums;transition:background .18s,color .18s}
  .tab.on b{background:rgba(0,0,0,.16);color:var(--pri-ink)}

  .grid{display:grid;gap:18px;grid-template-columns:minmax(0,1fr) clamp(400px,32vw,560px);align-items:start}
  .col{display:grid;gap:18px;min-width:0}
  .card{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:20px;box-shadow:var(--sh-1)}
  .card-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px;flex-wrap:wrap}
  .card-head h2{margin:0;font-family:var(--mono);font-size:10.5px;letter-spacing:.16em;
                text-transform:uppercase;color:var(--dim);font-weight:600}
  .card-head .meta{font-family:var(--mono);font-size:11.5px;color:var(--dim);font-variant-numeric:tabular-nums}
  .actions{display:flex;flex-wrap:wrap;align-items:center;gap:10px}
  .actions .err{flex:1 1 100%;margin-top:2px}

  .list table{width:100%;border-collapse:separate;border-spacing:0;font-size:13.5px}
  .list th{text-align:left;padding:0 10px 9px;border-bottom:1px solid var(--line);color:var(--dim);
           font-family:var(--mono);font-size:10px;letter-spacing:.12em;text-transform:uppercase;
           font-weight:600;white-space:nowrap}
  .list td{padding:11px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
  .list tbody tr{transition:background .16s ease}
  .list tbody tr:hover{background:var(--surface-2)}
  .list tbody tr:last-child td{border-bottom:0}
  .list td:first-child{font-weight:600}
  /* 备注：名字 + 一支常驻的铅笔，点哪个都能就地改名 */
  .list .lab-wrap{display:inline-flex;align-items:center;gap:6px;min-width:0;max-width:100%}
  .list .lab{cursor:pointer;max-width:190px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
             border-bottom:1px dashed transparent;transition:border-color .15s}
  .list .lab:hover{border-bottom-color:var(--dim)}
  .list .pen{width:26px;height:26px;padding:0;flex:0 0 auto;display:inline-grid;place-items:center;
             border:1px solid var(--line-2);border-radius:9px;background:var(--surface-2);
             color:var(--dim);cursor:pointer;box-shadow:none;
             transition:color .15s,border-color .15s,background .15s}
  .list .pen svg{width:13px;height:13px;fill:none;stroke:currentColor;stroke-width:2;
                 stroke-linecap:round;stroke-linejoin:round}
  .list .pen:hover,.list .pen:focus-visible{color:var(--pri);border-color:var(--pri);background:var(--surface)}
  .list .lab-edit{font:inherit;font-weight:600;font-size:13.5px;padding:5px 9px;width:auto;min-width:130px;
                  max-width:210px;border:1px solid var(--pri);border-radius:9px;background:var(--surface);
                  color:var(--txt);box-shadow:0 0 0 3px var(--ring);outline:none}
  .list .thint{color:var(--dim);font-size:11.5px;margin:9px 2px 0;opacity:.85}
  .list .num{font-family:var(--mono);font-variant-numeric:tabular-nums;font-size:13px}
  .list .time{font-family:var(--mono);font-size:11.5px;color:var(--dim)}
  .list table button{padding:6px 12px;border-radius:10px;font-size:12.5px;box-shadow:none}
  .list table button:hover{color:var(--bad);border-color:var(--bad);background:var(--bad-bg)}

  .tag{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;
       font-size:12px;font-weight:600;white-space:nowrap}
  .tag::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor;flex:0 0 auto}
  .t-ok{background:var(--ok-bg);color:var(--ok)}
  .t-warn{background:var(--warn-bg);color:var(--warn)}
  .t-bad{background:var(--bad-bg);color:var(--bad)}
  .t-idle{background:var(--idle-bg);color:var(--idle)}
  .hint{color:var(--dim);font-size:12.5px;margin-top:9px}
  code{font-family:var(--mono);font-size:11.5px;background:var(--idle-bg);color:var(--txt);padding:2px 6px;border-radius:6px}
  .empty{color:var(--dim);text-align:center;padding:26px 16px;font-size:13px}
  .err{color:var(--bad);font-size:13px;margin-top:10px;white-space:pre-wrap}

  @keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
  .card,.login-card,.topbar,.tabs{animation:rise .55s cubic-bezier(.22,.9,.28,1) both}
  .col>.card:nth-child(2){animation-delay:.06s}
  .col:nth-child(2)>.card{animation-delay:.12s}
  @media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}

  @media (max-width:1080px){
    .grid{grid-template-columns:minmax(0,1fr)}
    .topbar{position:static}
  }
  @media (max-width:640px){
    #loginView{min-height:auto;padding:36px 0}
    .list table,.list tbody,.list tr,.list td{display:block}
    .list thead{display:none}
    .list tbody{display:grid;gap:10px}
    .list tr{padding:12px 14px;border:1px solid var(--line);border-radius:14px;background:var(--surface-2)}
    .list td{display:flex;align-items:center;justify-content:space-between;gap:14px;
             padding:5px 0;border:0;text-align:right}
    .list td::before{content:attr(data-label);flex:0 0 auto;text-align:left;font-family:var(--mono);
             font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--dim)}
    .list td:first-child{font-size:15px;padding-bottom:9px;margin-bottom:5px;border-bottom:1px solid var(--line)}
    .list td:first-child::before{display:none}
    .list td.st{flex-wrap:wrap;justify-content:flex-end}
    .list td.st>div{flex:1 1 100%;text-align:right;margin-top:4px}
    .list td:last-child{padding-top:9px}
    .tab{padding:8px 13px;font-size:13px}
  }
</style>
</head>
<body>
<div class="wrap">

  <div id="loginView">
    <div class="brand">
      <span class="mark"><svg viewBox="0 0 24 24"><path d="M4.5 12.6l4.6 4.6L19.5 6.8"/></svg></span>
      <div>
        <div class="eyebrow">Daily Check-in</div>
        <h1>签到控制台</h1>
      </div>
    </div>

    <div class="login-card">
      <label class="lbl" for="pwd">登录密码</label>
      <div class="field">
        <input id="pwd" type="password" placeholder="输入登录密码" autocomplete="current-password">
        <button id="loginbtn" class="pri">登录</button>
      </div>
      <div class="hint">密码即后台的 <code>ADMIN_TOKEN</code>。登录状态存在本机浏览器，公共电脑用完请点「退出登录」。</div>
      <div class="err" id="loginErr"></div>
    </div>
  </div>

  <div id="mainView" hidden>
    <header class="topbar">
      <div class="brand">
        <span class="mark"><svg viewBox="0 0 24 24"><path d="M4.5 12.6l4.6 4.6L19.5 6.8"/></svg></span>
        <div>
          <div class="eyebrow">Daily Check-in</div>
          <h1>签到控制台</h1>
        </div>
      </div>
      <div class="row">
        <span class="chip"><i class="dot"></i>今日已签 <b id="statAll">—</b></span>
        <button id="runAll" class="pri">全部签到</button>
        <button id="logout">退出登录</button>
      </div>
    </header>

    <nav class="tabs">
      <button class="tab on" data-tab="trae">Trae <b id="cntTrae">0</b></button>
      <button class="tab" data-tab="wb">WorkBuddy <b id="cntWb">0</b></button>
    </nav>

    <section class="panel" id="panel-trae">
      <div class="grid">
        <div class="col">
          <div class="card actions">
            <button class="pri" data-run="trae">立即签到</button>
            <button data-refresh="trae">刷新</button>
            <div class="err" id="err-trae"></div>
          </div>
          <div class="card">
            <div class="card-head"><h2>Trae 账号</h2><span class="meta" id="lastRun-trae">—</span></div>
            <div class="list" id="list-trae"><div class="empty">加载中…</div></div>
          </div>
        </div>
        <div class="col">
          <div class="card">
            <div class="card-head"><h2>扫码登录 · Trae</h2></div>
            <div class="row">
              <button class="pri" id="traeQr">添加账号</button>
            </div>
            <div class="hint" id="traeQrStatus">点按钮打开官方登录页，用抖音扫码。登录完成后浏览器会停在一个打不开的本地页面，把地址栏里的整段链接复制过来即可。</div>
            <div id="traeQrFallback" style="margin-top:10px">
              <input id="traeQrUrl" placeholder="粘贴登录后地址栏的整段链接（127.0.0.1:17388/…）">
              <div class="row" style="margin-top:8px">
                <button id="traeQrClaim">绑定账号</button>
              </div>
              <div class="err" id="traeQrErr"></div>
            </div>
            <div class="hint">扫码走官网抖音授权，设备密钥由本服务现场生成并加密保存。全程无需在本机安装或运行任何东西。</div>
          </div>
        </div>
      </div>
    </section>

    <section class="panel" id="panel-wb" hidden>
      <div class="grid">
        <div class="col">
          <div class="card actions">
            <button class="pri" data-run="wb">立即签到</button>
            <button data-refresh="wb">刷新</button>
            <div class="err" id="err-wb"></div>
          </div>
          <div class="card">
            <div class="card-head"><h2>WorkBuddy 账号</h2><span class="meta" id="lastRun-wb">—</span></div>
            <div class="list" id="list-wb"><div class="empty">加载中…</div></div>
          </div>
        </div>
        <div class="col">
          <div class="card">
            <div class="card-head"><h2>扫码登录 · WorkBuddy</h2></div>
            <div class="row">
              <button class="pri" id="wbQr">添加账号</button>
            </div>
            <div class="hint" id="wbQrStatus">点按钮在新窗口打开官方登录页，用微信扫码并确认，账号会自动保存。</div>
            <div class="hint">二维码由官方登录页渲染，本服务不接触你的微信信息。</div>
          </div>
        </div>
      </div>
    </section>
  </div>

</div>
<script>
var $ = function(s){ return document.querySelector(s); };
var PWD_KEY = 'signin-admin-pwd';
var state = { tok:'', tab:'trae', data:{ trae:null, wb:null } };

function esc(s){ return String(s==null?'':s).replace(/[&<>"]/g, function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];
}); }
function fmt(n){ return n==null||n==='' ? '—' : String(n); }

/* 状态由服务端按当天判定（signedToday / ranToday），前端不自行推测 */
function bjToday(){
  return new Date(Date.now() + 8*3600e3).toISOString().slice(0,10);
}

function tagTrae(a, now){
  if(a.signedToday) return '<span class="tag t-ok">已签</span>';
  if(a.cooldownUntil && a.cooldownUntil > now){
    return '<span class="tag t-warn">限流 ' + Math.ceil((a.cooldownUntil-now)/60000) + ' 分钟</span>';
  }
  if(a.lastState==='token_dead') return '<span class="tag t-bad">令牌失效</span>';
  if(a.lastState==='pending' && a.ranToday) return '<span class="tag t-warn">待确认</span>';
  if(a.lastState==='error' && a.ranToday) return '<span class="tag t-bad">签到失败</span>';
  if(!a.hasKeys) return '<span class="tag t-warn">缺设备密钥</span>';
  return '<span class="tag t-idle">今日未签</span>';
}
function msgTrae(a){
  if(a.signedToday) return a.lastState==='checked' ? (a.lastMsg||'') : '';
  if(a.lastState==='token_dead') return a.lastMsg || '';
  if(a.lastState==='pending' && a.ranToday) return a.lastMsg || '';
  if(a.lastState==='error' && a.ranToday) return a.lastMsg || '';
  return '';
}

function tagWb(a){
  if(a.signedToday) return '<span class="tag t-ok">已签</span>';
  if(a.lastState==='token_dead') return '<span class="tag t-bad">令牌失效</span>';
  if(a.lastState==='error' && a.ranToday) return '<span class="tag t-bad">签到失败</span>';
  return '<span class="tag t-idle">今日未签</span>';
}
function msgWb(a){
  if(a.signedToday) return a.lastState==='checked' ? (a.lastMsg||'') : '';
  if(a.lastState==='token_dead') return a.lastMsg || '';
  if(a.lastState==='error' && a.ranToday) return a.lastMsg || '';
  return '';
}

function api(path, opts){
  opts = opts || {};
  return fetch(path, {
    method: opts.method || 'GET',
    body: opts.body,
    headers: { 'Content-Type':'application/json', 'X-Admin-Token': state.tok }
  }).then(function(res){
    return res.json().catch(function(){ return { error:'响应无法解析' }; }).then(function(data){
      if(res.status === 401){
        var msg = data.error || '登录已失效，请重新登录';
        logout(msg);
        throw new Error(msg);
      }
      if(!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
      return data;
    });
  });
}

function setLoginErr(m){ $('#loginErr').textContent = m ? String(m) : ''; }
function showErr(p, e){ $('#err-' + p).textContent = e ? String(e.message || e) : ''; }

/* ---------------- 登录 / 登出 ---------------- */

function login(password){
  var v = String(password==null?'':password).trim();
  if(!v){ setLoginErr('请输入登录密码'); return; }
  var btn = $('#loginbtn');
  btn.disabled = true; btn.textContent = '登录中…';
  return fetch('/api/ping', { headers: { 'X-Admin-Token': v } })
    .then(function(res){
      return res.json().catch(function(){ return { error:'响应无法解析' }; }).then(function(d){
        if(!res.ok) throw new Error(d.error || ('HTTP ' + res.status));
        state.tok = v;
        localStorage.setItem(PWD_KEY, v);
        setLoginErr('');
        $('#loginView').hidden = true;
        $('#mainView').hidden = false;
        loadAll();
      });
    })
    .catch(function(e){ setLoginErr(e.message || e); })
    .then(function(){ btn.disabled = false; btn.textContent = '登录'; });
}

function logout(msg){
  stopWbQr();
  state.tok = '';
  state.data = { trae:null, wb:null };
  localStorage.removeItem(PWD_KEY);
  $('#pwd').value = '';
  $('#list-trae').innerHTML = '<div class="empty">加载中…</div>';
  $('#list-wb').innerHTML = '<div class="empty">加载中…</div>';
  $('#statAll').textContent = '—';
  showErr('trae',''); showErr('wb','');
  setLoginErr(msg || '');
  $('#mainView').hidden = true;
  $('#loginView').hidden = false;
}

/* ---------------- 列表渲染 ---------------- */

function lastRunOf(list){
  var times = list.map(function(a){ return a.lastRun; }).filter(Boolean).sort();
  return times.length ? times[times.length-1].replace('T',' ').slice(0,16) : (list.length ? '暂无记录' : '暂无账号');
}

function renderTrae(d){
  var box = $('#list-trae'), now = Date.now();
  state.data.trae = d;
  $('#lastRun-trae').textContent = lastRunOf(d.accounts);
  $('#cntTrae').textContent = d.accounts.filter(function(a){ return a.signedToday; }).length + '/' + d.accounts.length;
  if(!d.accounts.length){ box.innerHTML = '<div class="empty">还没有账号，右侧扫码添加</div>'; return; }
  box.innerHTML = '<table><thead><tr><th>备注</th><th>状态</th><th>本次</th><th>余额</th><th>上次运行</th><th></th></tr></thead><tbody>'
    + d.accounts.map(function(a){
        var m = msgTrae(a);
        var gain = (a.lastState==='checked' && a.lastCredit!=null) ? '+' + a.lastCredit : '—';
        return '<tr>'
          + '<td class="labcell" data-label="备注">' + labCellHtml('trae', a.id, a.label) + '</td>'
          + '<td class="st" data-label="状态">' + tagTrae(a, now)
            + (m ? '<div class="hint" style="margin:2px 0 0">' + esc(m) + '</div>' : '') + '</td>'
          + '<td class="num" data-label="本次">' + gain + '</td>'
          + '<td class="num" data-label="余额">' + fmt(a.credits) + '</td>'
          + '<td class="time" data-label="上次运行">' + (a.lastRun ? esc(a.lastRun.replace('T',' ').slice(0,16)) : '—') + '</td>'
          + '<td data-label="操作"><button data-del="trae|' + esc(a.id) + '">删除</button></td>'
          + '</tr>';
      }).join('') + '</tbody></table>'
    + '<div class="thint">点账号名或右边的铅笔，可以改备注</div>';
  bindDel();
}

function renderWb(d){
  var box = $('#list-wb');
  var today = bjToday();
  // WorkBuddy 的列表接口只返回 lastOkDate / lastRun，这里按当天现算今日状态
  d.accounts.forEach(function(a){
    a.signedToday = a.lastOkDate === today;
    a.ranToday = !!a.lastRun && a.lastRun.slice(0,10) === today;
  });
  state.data.wb = d;
  $('#lastRun-wb').textContent = lastRunOf(d.accounts);
  $('#cntWb').textContent = d.accounts.filter(function(a){ return a.signedToday; }).length + '/' + d.accounts.length;
  if(!d.accounts.length){ box.innerHTML = '<div class="empty">还没有账号，右侧扫码添加</div>'; return; }
  box.innerHTML = '<table><thead><tr><th>备注</th><th>状态</th><th>连签</th><th>本期</th><th>上次运行</th><th></th></tr></thead><tbody>'
    + d.accounts.map(function(a){
        var m = msgWb(a);
        return '<tr>'
          + '<td class="labcell" data-label="备注">' + labCellHtml('wb', a.id, a.label) + '</td>'
          + '<td class="st" data-label="状态">' + tagWb(a)
            + (m ? '<div class="hint" style="margin:2px 0 0">' + esc(m) + '</div>' : '') + '</td>'
          + '<td class="num" data-label="连签">' + (a.streak==null ? '—' : a.streak + ' 天') + '</td>'
          + '<td class="num" data-label="本期">' + fmt(a.total) + '</td>'
          + '<td class="time" data-label="上次运行">' + (a.lastRun ? esc(a.lastRun.replace('T',' ').slice(0,16)) : '—') + '</td>'
          + '<td data-label="操作"><button data-del="wb|' + esc(a.id) + '">删除</button></td>'
          + '</tr>';
      }).join('') + '</tbody></table>'
    + '<div class="thint">点账号名或右边的铅笔，可以改备注</div>';
  bindDel();
}

/* 备注单元格：名字 + 常驻铅笔，点哪个都能就地改名 */
function labCellHtml(p, id, label){
  var k = 'data-rename="' + p + '|' + esc(id) + '" data-name="' + esc(label) + '"';
  return '<span class="lab-wrap">'
    + '<span class="lab" ' + k + ' title="点击修改备注">' + esc(label) + '</span>'
    + '<button class="pen" type="button" ' + k + ' title="修改备注" aria-label="修改备注">'
    + '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 20h3.6L19 8.6a2.2 2.2 0 0 0-3.1-3.1L4.5 16.9V20z"/></svg>'
    + '</button></span>';
}

/* 就地改名：把单元格换成输入框，回车/失焦保存，Esc 放弃 */
function startRename(el){
  var td = el.closest('td');
  if(!td || td.querySelector('.lab-edit')) return;
  var parts = el.dataset.rename.split('|');
  var p = parts[0], id = parts[1], old = el.dataset.name || '';
  td.innerHTML = '<input class="lab-edit" maxlength="40" aria-label="备注" ' +
                 'title="回车保存，Esc 取消" value="' + esc(old) + '">';
  var input = td.querySelector('.lab-edit');
  input.focus();
  input.select();

  var done = false;
  function restore(){ td.innerHTML = labCellHtml(p, id, old); bindDel(); }
  function finish(save){
    if(done) return;
    done = true;
    var v = input.value.trim();
    if(!save || !v || v === old){ restore(); return; }
    input.disabled = true;
    var url = p === 'trae' ? '/trae/api/rename' : '/wb/api/rename';
    api(url, { method:'POST', body: JSON.stringify({ id:id, label:v }) })
      .then(function(){ return load(p); })
      .catch(function(e){ showErr(p, e); restore(); });
  }
  input.addEventListener('keydown', function(ev){
    if(ev.key === 'Enter'){ ev.preventDefault(); finish(true); }
    else if(ev.key === 'Escape'){ ev.preventDefault(); finish(false); }
  });
  input.addEventListener('blur', function(){ finish(true); });
}

function bindDel(){
  document.querySelectorAll('[data-del]').forEach(function(b){
    b.onclick = function(){
      var parts = b.dataset.del.split('|');
      var p = parts[0], id = parts[1];
      if(!confirm('删除这个账号？')) return;
      var url = p === 'trae' ? '/trae/api/accounts/remove' : '/wb/api/remove';
      api(url, { method:'POST', body: JSON.stringify({ id:id }) })
        .then(function(){ return load(p); })
        .catch(function(e){ showErr(p, e); });
    };
  });

  document.querySelectorAll('[data-rename]').forEach(function(el){
    el.onclick = function(ev){ ev.stopPropagation(); startRename(el); };
  });
}

function renderStat(){
  var t = state.data.trae ? state.data.trae.accounts : null;
  var w = state.data.wb ? state.data.wb.accounts : null;
  if(t === null && w === null){ $('#statAll').textContent = '—'; return; }
  var all = (t || []).concat(w || []);
  var signed = all.filter(function(a){ return a.signedToday; }).length;
  $('#statAll').textContent = signed + ' / ' + all.length;
}

/* ---------------- 加载与签到 ---------------- */

function load(p){
  var url = p === 'trae' ? '/trae/api/list' : '/wb/api/list';
  return api(url)
    .then(function(d){ p === 'trae' ? renderTrae(d) : renderWb(d); renderStat(); })
    .catch(function(e){ showErr(p, e); renderStat(); });
}

function loadAll(){
  return Promise.all([load('trae'), load('wb')]);
}

function runOne(p){
  var btns = document.querySelectorAll('[data-run="' + p + '"]');
  btns.forEach(function(b){ b.disabled = true; b.textContent = '签到中…'; });
  showErr(p, '');
  var url = p === 'trae' ? '/trae/api/run?force=1' : '/wb/api/run?force=1';
  return api(url, { method:'POST', body:'{}' })
    .then(function(d){
      var bad = (d.results || []).filter(function(r){ return r.state==='error' || r.state==='token_dead'; });
      if(bad.length) showErr(p, bad.map(function(r){ return r.label + ': ' + r.msg; }).join('\\n'));
      return load(p);
    })
    .catch(function(e){ showErr(p, e); })
    .then(function(){
      btns.forEach(function(b){ b.disabled = false; b.textContent = '立即签到'; });
    });
}

function runAll(){
  var btn = $('#runAll');
  btn.disabled = true; btn.textContent = '签到中…';
  showErr('trae',''); showErr('wb','');
  api('/api/run-all?force=1', { method:'POST', body:'{}' })
    .then(function(d){
      var lines = [];
      ['trae','wb'].forEach(function(k){
        var r = d[k] || {};
        if(r.error){ lines.push((k==='trae'?'Trae':'WorkBuddy') + ': ' + r.error); return; }
        (r.results || []).forEach(function(x){
          if(x.state==='error' || x.state==='token_dead') lines.push(x.label + ': ' + x.msg);
        });
      });
      if(lines.length){
        showErr('trae', lines.join('\\n'));
      }
      return loadAll();
    })
    .catch(function(e){ showErr('trae', e); })
    .then(function(){ btn.disabled = false; btn.textContent = '全部签到'; });
}

/* ---------------- 标签页 ---------------- */

document.querySelectorAll('.tab').forEach(function(t){
  t.onclick = function(){
    var p = t.dataset.tab;
    state.tab = p;
    document.querySelectorAll('.tab').forEach(function(x){ x.classList.toggle('on', x === t); });
    $('#panel-trae').hidden = p !== 'trae';
    $('#panel-wb').hidden = p !== 'wb';
  };
});

/* ---------------- Trae 扫码登录 ---------------- */

function startTraeQr(){
  var btn = $('#traeQr');
  var old = btn.textContent;
  btn.disabled = true; btn.textContent = '准备中…';
  $('#traeQrErr').textContent = '';
  return api('/trae/api/login/start', { method:'POST', body: '{}' })
    .then(function(d){
      var w = window.open(d.authUrl, 'trae-login', 'width=520,height=820');
      if(!w){
        $('#traeQrStatus').innerHTML = '新窗口被拦截了：<a href="' + esc(d.authUrl) + '" target="_blank" rel="noopener">点这里打开登录页</a>';
      }else{
        $('#traeQrStatus').textContent = '已打开登录页：扫码登录，页面跳到一个打不开的 127.0.0.1 地址后，复制地址栏的整段链接粘到下面。';
        /* 登录完成后弹窗就会被关掉，这时把光标送到输入框 */
        var watch = setInterval(function(){
          if(!w || w.closed){ clearInterval(watch); $('#traeQrUrl').focus(); }
        }, 1200);
      }
    })
    .catch(function(e){ $('#traeQrStatus').textContent = String(e.message || e); })
    .then(function(){ btn.disabled = false; btn.textContent = old; });
}

/** 把粘贴进来的授权链接交给后端换取令牌并绑定账号 */
function claimTrae(){
  var btn = $('#traeQrClaim');
  var url = $('#traeQrUrl').value.trim();
  if(!url || btn.disabled) return;
  $('#traeQrErr').textContent = '';
  btn.disabled = true; btn.textContent = '绑定中…';
  api('/trae/api/login/claim', { method:'POST', body: JSON.stringify({ url: url }) })
    .then(function(d){
      $('#traeQrStatus').textContent = '登录成功，已保存为「' + d.label + '」';
      $('#traeQrUrl').value = '';
      return load('trae');
    })
    .catch(function(e){ $('#traeQrErr').textContent = String(e.message || e); })
    .then(function(){ btn.disabled = false; btn.textContent = '绑定账号'; });
}

$('#traeQr').onclick = startTraeQr;

$('#traeQrClaim').onclick = claimTrae;

/* 粘上就直接绑定，省掉再点一次按钮 */
$('#traeQrUrl').addEventListener('paste', function(){
  setTimeout(function(){ if($('#traeQrUrl').value.trim()) claimTrae(); }, 0);
});

/* 回调页若与本控制台同源，子窗口会直接通知这里 */
window.addEventListener('message', function(e){
  if(e.origin !== location.origin) return;
  var d = e.data || {};
  if(d.type !== 'trae-login') return;
  if(d.ok){
    $('#traeQrStatus').textContent = '登录成功，已保存为「' + (d.label || '') + '」';
    load('trae');
  }else{
    $('#traeQrStatus').textContent = '登录未完成，请重试';
  }
});

/* ---------------- WorkBuddy 扫码登录 ---------------- */

var wbState = '', wbTimer = null;
function stopWbQr(){ if(wbTimer){ clearInterval(wbTimer); wbTimer = null; } }

$('#wbQr').onclick = function(){
  stopWbQr();
  var btn = $('#wbQr');
  btn.disabled = true; btn.textContent = '获取中…';
  showErr('wb', '');

  /* 先同步开一个空窗口：官方登录页禁止被内嵌，只能整页打开；
     又因为后面要等接口返回，异步里再开窗会被弹窗拦截 */
  var win = window.open('about:blank', 'wb-login', 'width=640,height=880');

  api('/wb/api/login/start', { method:'POST', body:'{}' })
    .then(function(d){
      wbState = d.state;
      var opened = false;
      if(win && !win.closed){
        try { win.location.href = d.authUrl; opened = true; } catch(e) { opened = false; }
      }
      if(opened){
        $('#wbQrStatus').textContent = '已在新窗口打开登录页，用微信扫码并确认，本页会自动保存账号。';
      }else{
        $('#wbQrStatus').innerHTML = '新窗口被拦截了：'
          + '<a href="' + esc(d.authUrl) + '" target="_blank" rel="noopener">点这里打开登录页</a>';
      }
      btn.textContent = '添加账号';
      btn.disabled = false;

      var n = 0;
      wbTimer = setInterval(function(){
        if(n++ > 150){
          stopWbQr();
          $('#wbQrStatus').textContent = '二维码已过期，请点「添加账号」重试';
          return;
        }
        api('/wb/api/login/poll?state=' + encodeURIComponent(wbState)).then(function(r){
          if(r.status === 'ok'){
            stopWbQr();
            if(win && !win.closed){ try { win.close(); } catch(e){} }
            $('#wbQrStatus').textContent = '登录成功，已保存为「' + r.label + '」';
            load('wb');
          }
        }).catch(function(e){
          stopWbQr();
          $('#wbQrStatus').textContent = String(e.message || e);
        });
      }, 2500);
    })
    .catch(function(e){
      if(win && !win.closed){ try { win.close(); } catch(err){} }
      showErr('wb', e);
      btn.textContent = '添加账号';
      btn.disabled = false;
    });
};

/* ---------------- 事件绑定 ---------------- */

$('#loginbtn').onclick = function(){ login($('#pwd').value); };
$('#pwd').onkeydown = function(e){ if(e.key === 'Enter') login($('#pwd').value); };
$('#logout').onclick = function(){ if(confirm('退出登录？')) logout(''); };
$('#runAll').onclick = runAll;

document.querySelectorAll('[data-run]').forEach(function(b){
  b.onclick = function(){ runOne(b.dataset.run); };
});
document.querySelectorAll('[data-refresh]').forEach(function(b){
  b.onclick = function(){ load(b.dataset.refresh); };
});

/* 页面挂着过夜也能自动翻篇：只在日期真的变了才重新拉列表 */
var dayMark = bjToday();
setInterval(function(){
  var d = bjToday();
  if(d !== dayMark){ dayMark = d; if(state.tok) loadAll(); }
}, 60000);

var saved = localStorage.getItem(PWD_KEY);
if(saved) login(saved);
</script>
</body>
</html>`;

/* ------------------------------------------------------------------ */
/* 入口                                                                */
/* ------------------------------------------------------------------ */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const method = request.method.toUpperCase();

    try {
      if (path === '/' || path === '/index.html') return htmlResponse(PAGE);

      if (path === '/cron') {
        const c = requireCron(request, env);
        if (!c.ok) return c.res;
        return json(await runAll(env, url.origin, false));
      }

      // Trae 的授权链接里回调地址写死为 <origin>/oauth/callback，必须留在根路径
      if (path === '/oauth/callback' && method === 'GET') return await Trae.fetch(request, traeEnv(env), ctx);
      if (path === '/oauth/probe') {
        return new Response('ok', { headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' } });
      }

      if (path === '/api/ping' && method === 'GET') {
        const a = requireAdmin(request, env);
        return a.ok ? json({ ok: true }) : a.res;
      }

      if (path === '/api/run-all' && method === 'POST') {
        const a = requireAdmin(request, env);
        if (!a.ok) return a.res;
        const force = url.searchParams.get('force') === '1';
        return json(await runAll(env, url.origin, force));
      }

      // 平台命名空间：/trae/api/* → 模块内的 /api/*
      if (path === '/trae' || path === '/wb') return Response.redirect(url.origin + '/', 302);
      if (path.startsWith('/trae/')) {
        return await Trae.fetch(repath(request, path.slice(5) || '/'), traeEnv(env), ctx);
      }
      if (path.startsWith('/wb/')) {
        return await WorkBuddy.fetch(repath(request, path.slice(3) || '/'), wbEnv(env), ctx);
      }

      return json({ error: 'not found' }, 404);
    } catch (e) {
      return json({ error: e.message || String(e) }, 500);
    }
  },

  /** Cloudflare Cron Trigger：两个平台依次签到，互不影响 */
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      (async () => {
        const pending = [];
        const sink = { waitUntil: (p) => pending.push(p) };
        for (const [mod, e] of [
          [Trae, traeEnv(env)],
          [WorkBuddy, wbEnv(env)],
        ]) {
          try {
            await mod.scheduled({}, e, sink);
          } catch {
            /* 一个平台整体失败不影响另一个 */
          }
        }
        await Promise.allSettled(pending);
      })()
    );
  },
};
