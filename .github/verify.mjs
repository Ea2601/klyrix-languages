#!/usr/bin/env node
// İmzalı dil listesi (index.json) doğrulayıcısı. TEK BAŞINA çalışır (yalnız Node yerleşikleri, başka dosyaya bağımlı
// değil): aynı dosya açık paket deposunda .github/verify.mjs olarak durur ve Release'ten önce imzayı denetler.
//
// Zarf: { "kid": "<anahtar kimliği>", "sig": "<Ed25519 imzası, base64url>", "payload": "<JSON dizgisi>" }
//   - İmza payload dizgisinin UTF-8 baytları üzerindedir (kanonikleştirme yok: imzalanan şey dizginin kendisi).
//   - kid açık anahtar listesinde olmalı; rol 'ci' (CI anahtarı) ya da 'yedek' (çevrimdışı yedek anahtar).
//   - payload.revoked: null ya da YEDEK anahtarla imzalı iç zarf ({ kid, sig, payload: {format, tur:'iptal', kids, created} }).
//     İç zarf hangi anahtarla imzalanmış olursa olsun yalnız 'yedek' rolündeki kid ile doğrulanırsa geçerlidir.
//
// Kullanım:
//   node dogrula.mjs <index.json> <acik-anahtarlar.json> [--paketler <taban klasör>] [--etiket lp-<n>]
//   --paketler: index'teki her paketin dosyasını <klasör>/<path> altında arar; bayt sayısı ve sha256 denetlenir.
//   --etiket: payload.seq etiketteki numarayla aynı olmalı.
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import zlib from 'node:zlib'
import { fileURLToPath } from 'node:url'

export const FORMAT = 1
const B64URL = /^[A-Za-z0-9_-]+$/
const PATH_RE = /^lp-[0-9]{1,9}\/[a-z]{2,3}(-[a-z0-9]{2,8})*\.json\.gz$/
const CODE_RE = /^[a-z]{2,3}(-[a-z0-9]{2,8})*$/

/** Ham 32 baytlık açık anahtar (base64url, 43 karakter) → KeyObject; bozuksa null. */
export function publicKeyFromRaw(raw) {
  if (typeof raw !== 'string' || raw.length !== 43 || !B64URL.test(raw)) return null
  try {
    const k = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: raw }, format: 'jwk' })
    return k.asymmetricKeyType === 'ed25519' ? k : null
  } catch { return null }
}

/** Açık anahtar listesi: { keys: [{ kid, rol, raw }] } → Map kid → { rol, key }. */
export function loadKeys(obj) {
  const m = new Map()
  for (const k of obj?.keys || []) {
    const key = publicKeyFromRaw(k.raw)
    if (key && typeof k.kid === 'string' && (k.rol === 'ci' || k.rol === 'yedek')) m.set(k.kid, { rol: k.rol, key })
  }
  return m
}

function verifySig(env, keys) {
  if (!env || typeof env !== 'object' || Array.isArray(env)) return { ok: false, error: 'zarf nesne değil' }
  const { kid, sig, payload } = env
  if (typeof kid !== 'string' || typeof sig !== 'string' || typeof payload !== 'string') return { ok: false, error: 'zarf alanları eksik' }
  const k = keys.get(kid)
  if (!k) return { ok: false, error: `bilinmeyen anahtar: ${kid.slice(0, 40)}` }
  if (sig.length !== 86 || !B64URL.test(sig)) return { ok: false, error: 'imza biçimi geçersiz' }
  let good = false
  try { good = crypto.verify(null, Buffer.from(payload, 'utf8'), k.key, Buffer.from(sig, 'base64url')) } catch { good = false }
  if (!good) return { ok: false, error: 'imza doğrulanamadı' }
  let p
  try { p = JSON.parse(payload) } catch { return { ok: false, error: 'payload JSON değil' } }
  return { ok: true, kid, rol: k.rol, payload: p }
}

/**
 * index.json zarfını doğrular. revokedSeen: cihazın daha önce gördüğü iptal edilmiş kid'ler (araçta boş).
 * @returns {{ ok: true, kid: string, rol: string, payload: any, revoked: string[] } | { ok: false, error: string }}
 */
export function verifyIndex(env, keys, revokedSeen = []) {
  const r = verifySig(env, keys)
  if (!r.ok) return r
  const p = r.payload
  if (!p || typeof p !== 'object' || p.format !== FORMAT) return { ok: false, error: `desteklenmeyen biçim: ${p?.format}` }
  if (!Number.isInteger(p.seq) || p.seq < 1) return { ok: false, error: 'seq geçersiz' }
  let revoked = [...revokedSeen]
  if (p.revoked != null) {
    const iv = verifySig(p.revoked, keys)
    if (!iv.ok) return { ok: false, error: `iptal listesi: ${iv.error}` }
    if (iv.rol !== 'yedek') return { ok: false, error: 'iptal listesini yalnız yedek anahtar imzalayabilir' }
    if (iv.payload?.format !== FORMAT || iv.payload?.tur !== 'iptal' || !Array.isArray(iv.payload?.kids)) return { ok: false, error: 'iptal listesi biçimi geçersiz' }
    revoked = [...new Set([...revoked, ...iv.payload.kids.filter(x => typeof x === 'string')])]
  }
  if (revoked.includes(r.kid)) return { ok: false, error: `iptal edilmiş anahtar: ${r.kid}` }
  for (const list of ['langs', 'embedded']) {
    if (!Array.isArray(p[list])) return { ok: false, error: `${list} dizi değil` }
    for (const l of p[list]) {
      if (!CODE_RE.test(l?.code || '') || !PATH_RE.test(l?.path || '') || !/^[0-9a-f]{64}$/.test(l?.sha256 || '')
        || !Number.isInteger(l?.bytes) || !Number.isInteger(l?.rawBytes)) return { ok: false, error: `${list}: girdi geçersiz (${String(l?.code).slice(0, 12)})` }
    }
  }
  if (!Array.isArray(p.mirrors) || !p.mirrors.every(m => typeof m === 'string' && m.startsWith('https://') && m.endsWith('/'))) return { ok: false, error: 'mirrors geçersiz' }
  return { ok: true, kid: r.kid, rol: r.rol, payload: p, revoked }
}

/** Paket dosyasını index girdisine göre denetler ve açar: bayt, sha256, gunzip (en çok 10 MB), şema. */
export function openPack(buf, entry, maxRaw = 10 * 1024 * 1024) {
  if (buf.length !== entry.bytes) throw new Error(`${entry.code}: bayt sayısı tutmuyor (${buf.length} ≠ ${entry.bytes})`)
  const sha = crypto.createHash('sha256').update(buf).digest('hex')
  if (sha !== entry.sha256) throw new Error(`${entry.code}: sha256 tutmuyor`)
  const raw = zlib.gunzipSync(buf, { maxOutputLength: maxRaw })
  if (raw.length !== entry.rawBytes) throw new Error(`${entry.code}: açılmış boyut tutmuyor`)
  const obj = JSON.parse(raw.toString('utf8'))
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new Error(`${entry.code}: paket nesne değil`)
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v?.t !== 'string' || !v.t || v.t.length > 4000 || !/^[0-9a-f]{8}$/.test(v?.src || '')) throw new Error(`${entry.code}: girdi geçersiz (${k.slice(0, 60)})`)
    if (v.h !== undefined && (!Array.isArray(v.h) || v.h.length > 3)) throw new Error(`${entry.code}: h geçersiz (${k.slice(0, 60)})`)
  }
  return obj
}

// ─── komut satırı ───
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2)
  const opt = n => { const i = args.indexOf('--' + n); return i >= 0 ? args[i + 1] : undefined }
  const [indexFile, keysFile] = args
  if (!indexFile || !keysFile) { console.error('kullanım: node dogrula.mjs <index.json> <acik-anahtarlar.json> [--paketler <klasör>] [--etiket lp-<n>]'); process.exit(2) }
  const keys = loadKeys(JSON.parse(fs.readFileSync(keysFile, 'utf8')))
  const raw = fs.readFileSync(indexFile)
  if (raw.length > 256 * 1024) { console.error('index.json 256 kB sınırını aşıyor'); process.exit(1) }
  const r = verifyIndex(JSON.parse(raw.toString('utf8')), keys)
  if (!r.ok) { console.error(`DOĞRULANAMADI: ${r.error}`); process.exit(1) }
  const tag = opt('etiket')
  if (tag !== undefined && tag !== `lp-${r.payload.seq}`) { console.error(`etiket (${tag}) ile seq (${r.payload.seq}) uyuşmuyor`); process.exit(1) }
  const base = opt('paketler')
  let checked = 0
  if (base) {
    for (const e of [...r.payload.langs, ...r.payload.embedded]) {
      openPack(fs.readFileSync(path.join(base, e.path)), e)
      checked++
    }
  }
  console.log(`imza geçerli: seq ${r.payload.seq}, anahtar ${r.kid} (${r.rol}), ${r.payload.langs.length} dil + ${r.payload.embedded.length} gömülü` + (base ? `, ${checked} paket denetlendi` : ''))
}
