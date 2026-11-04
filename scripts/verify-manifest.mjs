#!/usr/bin/env node
/**
 * Verificador del manifiesto firmado de ECCu para el repo público
 * maular22/eccu-manifest. Un solo archivo, sin dependencias, solo módulos
 * integrados de Node 20. NUNCA firma: solo verifica.
 *
 * Es una copia a mano de las reglas de referencia del repo privado
 * (src/common/manifest/{jcs,ed25519,manifest.rules}.ts + contract/manifest.md).
 * Una prueba de paridad en el repo privado corre este archivo contra todos los
 * vectores para que las dos copias no se separen. Si cambias uno, cambia el otro.
 *
 * Uso:
 *   node scripts/verify-manifest.mjs --environment production|qa \
 *     [--manifest production.json] [--keys keys/production.json] \
 *     [--previous <archivo>|none | --previous-ref HEAD~1] \
 *     [--mode change|daily] [--min-days-left 7] [--now <ISO>] [--json] \
 *     [--reject-expired]
 *   node scripts/verify-manifest.mjs --jcs <archivo.json>   (imprime el JSON canónico)
 *
 * Modos: change (defecto) compara con la base de confianza (--previous-ref;
 * verifica contra las llaves de la base; si keys/ cambió sale 3); daily no
 * compara: 1 firma válida de las llaves fijadas.
 * Salida: 0 = válido (o marcador "sin publicar"), 1 = inválido o vencido,
 * 2 = válido pero vence en menos de --min-days-left días, 3 = llaves cambiadas.
 */
import { createPublicKey, verify } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

// ---------------------------------------------------------------- JCS (RFC 8785)

const SURROGATE_SUELTO =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function texto(s) {
  if (SURROGATE_SUELTO.test(s)) {
    throw new Error('JSON canónico: texto con surrogate suelto');
  }
  return JSON.stringify(s);
}

export function canonicalize(value) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'string':
      return texto(value);
    case 'number':
      if (!Number.isSafeInteger(value)) {
        throw new Error('JSON canónico: solo se permiten enteros seguros');
      }
      return Object.is(value, -0) ? '0' : String(value);
    case 'object': {
      if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) {
          if (!(i in value))
            throw new Error('JSON canónico: arreglo con huecos');
        }
        return `[${value.map((v) => canonicalize(v)).join(',')}]`;
      }
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) {
        throw new Error('JSON canónico: solo objetos planos');
      }
      if (Object.getOwnPropertySymbols(value).length > 0) {
        throw new Error('JSON canónico: claves symbol no permitidas');
      }
      const parts = Object.keys(value)
        .sort()
        .map((k) => `${texto(k)}:${canonicalize(value[k])}`);
      return `{${parts.join(',')}}`;
    }
    default:
      throw new Error(`JSON canónico: tipo no permitido (${typeof value})`);
  }
}

// ---------------------------------------------------------------- Ed25519 estricto

const B64U = /^[A-Za-z0-9_-]+$/;

export function ed25519Verify(publicKeySpkiB64u, data, sigB64u) {
  try {
    if (typeof publicKeySpkiB64u !== 'string' || typeof sigB64u !== 'string') {
      return false;
    }
    if (!Buffer.isBuffer(data)) return false;
    if (!B64U.test(publicKeySpkiB64u) || !B64U.test(sigB64u)) return false;
    const sig = Buffer.from(sigB64u, 'base64url');
    if (sig.length !== 64 || sig.toString('base64url') !== sigB64u)
      return false;
    const der = Buffer.from(publicKeySpkiB64u, 'base64url');
    if (der.length !== 44 || der.toString('base64url') !== publicKeySpkiB64u) {
      return false;
    }
    const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ed25519') return false;
    if (!key.export({ type: 'spki', format: 'der' }).equals(der)) return false;
    return verify(null, data, key, sig);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------- Lector sin claves repetidas

export function parseManifestText(text) {
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    return { ok: false, reason: 'json' };
  }
  const stack = [];
  let expectKey = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      if (expectKey) {
        const key = JSON.parse(text.slice(i, j + 1));
        const keys = stack[stack.length - 1];
        if (keys.has(key)) return { ok: false, reason: 'duplicate_key' };
        keys.add(key);
        expectKey = false;
      }
      i = j;
    } else if (c === '{') {
      stack.push(new Set());
      expectKey = true;
    } else if (c === '[') {
      stack.push(null);
    } else if (c === '}' || c === ']') {
      stack.pop();
      expectKey = false;
    } else if (c === ',') {
      expectKey = stack.length > 0 && stack[stack.length - 1] !== null;
    }
  }
  return { ok: true, value };
}

// ---------------------------------------------------------------- Esquema (a mano)
// Equivalente a contract/manifest/manifest.schema.json (JSON Schema 2020-12).

const re = (p) => new RegExp(p, 'u');
const RE_BASE = re(
  '^https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$',
);
const RE_SOURCE = re(
  '^https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(/(?!\\.{1,2}(?:/|$))[A-Za-z0-9._~-]+)+$',
);
const RE_KEYID = re('^[a-z0-9-]{3,40}$');
const RE_SEMVER = re('^[0-9]{1,5}\\.[0-9]{1,5}\\.[0-9]{1,5}$');
const RE_SIG = re('^[A-Za-z0-9_-]{86}$');
const RE_DATE = re(
  '^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$',
);
const NOTICE_CODES = ['maintenance', 'server_change', 'degraded'];

const isObj = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const cpLen = (s) => [...s].length; // Ajv cuenta puntos de código en maxLength
const onlyKeys = (o, allowed) =>
  Object.keys(o).every((k) => allowed.includes(k));
const hasAll = (o, req) =>
  req.every((k) => Object.prototype.hasOwnProperty.call(o, k));
const posInt = (v) => Number.isSafeInteger(v) && v >= 1;
const str = (v, rx, max) =>
  typeof v === 'string' && cpLen(v) <= max && (rx === null || rx.test(v));

function dateTime(v) {
  if (!str(v, RE_DATE, 20)) return false;
  const [, y, mo, d, h, mi, s] = RE_DATE.exec(v).map(Number);
  if (mo < 1 || mo > 12 || h > 23 || mi > 59 || s > 59) return false;
  const t = new Date(0);
  t.setUTCFullYear(y, mo - 1, d);
  t.setUTCHours(h, mi, s, 0);
  return t.getUTCDate() === d && t.getUTCMonth() === mo - 1;
}

function strList(v, rx, max, maxItems, minItems) {
  return (
    Array.isArray(v) &&
    v.length >= minItems &&
    v.length <= maxItems &&
    v.every((x) => str(x, rx, max)) &&
    new Set(v).size === v.length
  );
}

const SIGNED_REQUIRED = [
  'type',
  'spec',
  'version',
  'issuedAt',
  'expiresAt',
  'environment',
  'epoch',
  'active',
  'standby',
  'manifestSources',
  'minAppVersion',
];

function validSignature(s) {
  return (
    isObj(s) &&
    onlyKeys(s, ['keyId', 'alg', 'sig']) &&
    hasAll(s, ['keyId', 'alg', 'sig']) &&
    str(s.keyId, RE_KEYID, 40) &&
    s.alg === 'Ed25519' &&
    str(s.sig, RE_SIG, 86)
  );
}

function validSigned(s) {
  if (!isObj(s)) return false;
  if (!onlyKeys(s, [...SIGNED_REQUIRED, 'noticeCode', 'revokedKeys', 'pins']))
    return false;
  if (!hasAll(s, SIGNED_REQUIRED)) return false;
  if (s.type !== 'eccu-endpoints' || s.spec !== 1) return false;
  if (!posInt(s.version) || !posInt(s.epoch)) return false;
  if (!dateTime(s.issuedAt) || !dateTime(s.expiresAt)) return false;
  if (s.environment !== 'qa' && s.environment !== 'production') return false;
  const a = s.active;
  if (
    !isObj(a) ||
    !onlyKeys(a, ['site', 'baseUrls']) ||
    !hasAll(a, ['site', 'baseUrls'])
  ) {
    return false;
  }
  if (
    !(typeof a.site === 'string' && cpLen(a.site) >= 1 && cpLen(a.site) <= 64)
  ) {
    return false;
  }
  if (!strList(a.baseUrls, RE_BASE, 253, 8, 1)) return false;
  const sb = s.standby;
  if (!isObj(sb) || !onlyKeys(sb, ['site']) || !hasAll(sb, ['site']))
    return false;
  if (
    !(
      typeof sb.site === 'string' &&
      cpLen(sb.site) >= 1 &&
      cpLen(sb.site) <= 64
    )
  ) {
    return false;
  }
  if (!strList(s.manifestSources, RE_SOURCE, 512, 8, 1)) return false;
  const m = s.minAppVersion;
  if (
    !isObj(m) ||
    !onlyKeys(m, ['ios', 'android']) ||
    !hasAll(m, ['ios', 'android'])
  ) {
    return false;
  }
  if (!str(m.ios, RE_SEMVER, 100) || !str(m.android, RE_SEMVER, 100))
    return false;
  if ('noticeCode' in s && !NOTICE_CODES.includes(s.noticeCode)) return false;
  if ('revokedKeys' in s && !strList(s.revokedKeys, RE_KEYID, 40, 16, 0))
    return false;
  if ('pins' in s && !isObj(s.pins)) return false;
  return true;
}

function validEnvelope(e) {
  return (
    isObj(e) &&
    onlyKeys(e, ['signed', 'signatures']) &&
    hasAll(e, ['signed', 'signatures']) &&
    validSigned(e.signed) &&
    Array.isArray(e.signatures) &&
    e.signatures.length >= 1 &&
    e.signatures.length <= 8 &&
    e.signatures.every(validSignature)
  );
}

// ---------------------------------------------------------------- Reglas

const FUTURE_SKEW_MS = 10 * 60 * 1000;
const MAX_VERSION_JUMP = 50;
const MAX_VALIDITY_MS = 90 * 24 * 60 * 60 * 1000;

const fail = (reason) => ({ ok: false, reason });

function semverGreater(a, b) {
  const x = a.split('.').map(Number);
  const y = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if (x[i] !== y[i]) return x[i] > y[i];
  }
  return false;
}

const pinsKey = (m) => canonicalize(m.pins ?? null);

export function isGraveChange(signed, prev) {
  if (!prev) return true;
  if (signed.active.site !== prev.active.site) return true;
  if (signed.epoch !== prev.epoch) return true;
  const before = new Set(prev.revokedKeys ?? []);
  if ((signed.revokedKeys ?? []).some((k) => !before.has(k))) return true;
  const knownBase = new Set(prev.active.baseUrls);
  if (signed.active.baseUrls.some((u) => !knownBase.has(u))) return true;
  const knownSrc = new Set(prev.manifestSources);
  if (signed.manifestSources.some((u) => !knownSrc.has(u))) return true;
  const nowSrc = new Set(signed.manifestSources);
  if (prev.manifestSources.some((u) => !nowSrc.has(u))) return true;
  if (
    semverGreater(signed.minAppVersion.ios, prev.minAppVersion.ios) ||
    semverGreater(signed.minAppVersion.android, prev.minAppVersion.android)
  ) {
    return true;
  }
  try {
    return pinsKey(signed) !== pinsKey(prev);
  } catch {
    return true;
  }
}

/**
 * ctx: { publicKeys: Map<keyId, spkiB64u>, environment, previous|null, now: Date,
 *        standalone?: boolean, rejectExpired?: boolean }
 * `standalone` (manifiesto sin cambios frente al anterior, p. ej. la corrida
 * diaria): no hay "anterior" contra el cual comparar; basta 1 firma válida de
 * una llave fijada que el propio manifiesto no revoque.
 */
export function verifyManifest(env, ctx) {
  if (!validEnvelope(env)) return fail('schema');
  const { signed, signatures } = env;
  if (signed.environment !== ctx.environment) return fail('environment');

  const issued = Date.parse(signed.issuedAt);
  const expires = Date.parse(signed.expiresAt);
  if (!(expires > issued)) return fail('expires_before_issued');
  if (expires - issued > MAX_VALIDITY_MS) return fail('validity_too_long');
  if (issued > ctx.now.getTime() + FUTURE_SKEW_MS)
    return fail('issued_in_future');
  if (ctx.rejectExpired && ctx.now.getTime() > expires) return fail('expired');

  const prev = ctx.previous;
  const nowRevoked = new Set(signed.revokedKeys ?? []);
  if ((prev?.revokedKeys ?? []).some((k) => !nowRevoked.has(k))) {
    return fail('revocation_dropped');
  }
  const revoked = new Set(prev?.revokedKeys ?? []);
  if (ctx.standalone) for (const k of nowRevoked) revoked.add(k);
  let bytes;
  try {
    bytes = Buffer.from(canonicalize(signed), 'utf8');
  } catch {
    return fail('schema');
  }
  const valid = new Set();
  for (const s of signatures) {
    if (revoked.has(s.keyId) || valid.has(s.keyId)) continue;
    const pub = ctx.publicKeys.get(s.keyId);
    if (pub === undefined) continue;
    if (ed25519Verify(pub, bytes, s.sig)) valid.add(s.keyId);
  }
  const needed = ctx.standalone ? 1 : isGraveChange(signed, prev) ? 2 : 1;
  if (valid.size < needed) return fail('signatures');

  if (prev) {
    if (signed.version <= prev.version) return fail('not_newer');
    if (signed.version > prev.version + MAX_VERSION_JUMP)
      return fail('version_jump');
    if (signed.epoch < prev.epoch) return fail('epoch_regressed');
    if (issued < Date.parse(prev.issuedAt))
      return fail('issued_before_previous');
  }
  return { ok: true, manifest: signed, expired: ctx.now.getTime() > expires };
}

// ---------------------------------------------------------------- CLI

const KNOWN_FLAGS = [
  'environment',
  'manifest',
  'keys',
  'previous',
  'previous-ref',
  'mode',
  'min-days-left',
  'now',
  'json',
  'jcs',
  'reject-expired',
];

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (!flag.startsWith('--') || !KNOWN_FLAGS.includes(flag.slice(2))) {
      return { error: `Argumento desconocido: ${flag}` };
    }
    const name = flag.slice(2);
    if (name === 'json' || name === 'reject-expired') {
      out[name === 'json' ? 'json' : 'rejectExpired'] = true;
      continue;
    }
    const value = argv[++i];
    if (value === undefined || value.startsWith('--')) {
      return { error: `Falta el valor de ${flag}` };
    }
    out[name] = value;
  }
  return out;
}

const isPlaceholder = (v) =>
  isObj(v) && Object.keys(v).length === 1 && typeof v._note === 'string';

function readParsed(path, label) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    return { error: `No pude leer ${label}: ${path}` };
  }
  return readText(text, label);
}

function readText(text, label) {
  const p = parseManifestText(text);
  if (!p.ok) {
    return {
      reason: p.reason,
      error:
        p.reason === 'duplicate_key'
          ? `${label} tiene claves repetidas`
          : `${label} no es JSON válido`,
    };
  }
  return { value: p.value, text };
}

function keysFromValue(value) {
  const list = isObj(value) && Array.isArray(value.keys) ? value.keys : value;
  if (!Array.isArray(list)) {
    return { error: 'Las llaves deben ser una lista [{"keyId","publicKey"}].' };
  }
  const keys = new Map();
  for (const e of list) {
    if (
      !isObj(e) ||
      typeof e.keyId !== 'string' ||
      typeof e.publicKey !== 'string' ||
      keys.has(e.keyId)
    ) {
      return {
        error: 'Las llaves tienen una entrada inválida o un keyId repetido.',
      };
    }
    keys.set(e.keyId, e.publicKey);
  }
  return { keys };
}

function readKeys(path) {
  const r = readParsed(path, 'las llaves');
  return r.error ? r : keysFromValue(r.value);
}

const sameKeys = (a, b) =>
  a.size === b.size && [...a].every(([id, pk]) => b.get(id) === pk);

function git(args) {
  try {
    return execFileSync('git', args, {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    });
  } catch {
    return null;
  }
}

export function main(argv, io = { out: console.log, err: console.error }) {
  const args = parseArgs(argv);
  if (args.error) {
    io.err(args.error);
    return 1;
  }

  if (args.jcs !== undefined) {
    const r = readParsed(args.jcs, '--jcs');
    if (r.error) {
      io.err(r.error);
      return 1;
    }
    try {
      process.stdout.write(canonicalize(r.value));
      return 0;
    } catch (e) {
      io.err(e.message);
      return 1;
    }
  }

  const envName = args.environment;
  if (envName !== 'production' && envName !== 'qa') {
    io.err('--environment debe ser production o qa.');
    return 1;
  }
  const manifestPath = args.manifest ?? `${envName}.json`;
  const keysPath = args.keys ?? `keys/${envName}.json`;
  const now = args.now ? new Date(args.now) : new Date();
  if (Number.isNaN(now.getTime())) {
    io.err('--now no es una fecha válida.');
    return 1;
  }
  const minDays =
    args['min-days-left'] === undefined ? null : Number(args['min-days-left']);
  if (minDays !== null && !(minDays >= 0)) {
    io.err('--min-days-left debe ser un número.');
    return 1;
  }
  const report = (obj, code) => {
    if (args.json) io.out(JSON.stringify(obj));
    return code;
  };
  const say = (msg) => {
    if (!args.json) io.out(msg);
  };

  const m = readParsed(manifestPath, 'el manifiesto');
  if (m.error) {
    io.err(m.error);
    return report({ ok: false, reason: m.reason ?? 'json' }, 1);
  }
  const mode = args.mode ?? 'change';
  if (mode !== 'change' && mode !== 'daily') {
    io.err('--mode debe ser change o daily.');
    return 1;
  }

  // Manifiesto y llaves de la base de confianza (el estado ANTERIOR)
  let prevText = null; // { value, text } | null
  let baseKeysValue = null; // valor JSON de keys/<env>.json en la base
  let fromGit = false;
  if (mode === 'change') {
    if (args.previous !== undefined && args.previous !== 'none') {
      const p = readParsed(args.previous, '--previous');
      if (p.error) {
        io.err(p.error);
        return 1;
      }
      prevText = p;
    } else if (args.previous === undefined && args['previous-ref']) {
      const ref = args['previous-ref'];
      fromGit = true;
      const resolved = git([
        'rev-parse',
        '--verify',
        '--quiet',
        `${ref}^{commit}`,
      ]);
      if (resolved === null) {
        const head = git(['rev-parse', 'HEAD']);
        const roots = git(['rev-list', '--max-parents=0', 'HEAD']);
        const isRoot =
          head !== null &&
          roots !== null &&
          roots.trim().split('\n').includes(head.trim());
        if (!isRoot) {
          io.err(
            `[${envName}] La referencia "${ref}" no se pudo resolver en git (¿falta fetch-depth o el fetch de la rama base?). No se puede verificar contra la base.`,
          );
          return report({ ok: false, reason: 'ref' }, 1);
        }
        // primer commit del repo: no hay anterior (el primero lleva 2 firmas)
      } else {
        if (git(['cat-file', '-e', `${ref}:${manifestPath}`]) !== null) {
          const text = git(['show', `${ref}:${manifestPath}`]);
          const p = readText(text ?? '', 'el manifiesto anterior (git)');
          if (p.error) {
            io.err(p.error);
            return 1;
          }
          prevText = p;
        }
        const kt = git(['show', `${ref}:${keysPath}`]);
        if (kt !== null) {
          const kp = readText(kt, 'las llaves anteriores (git)');
          if (kp.error) {
            io.err(kp.error);
            return 1;
          }
          baseKeysValue = kp.value;
        }
      }
    }
  }
  const prevReal = prevText !== null && !isPlaceholder(prevText.value);

  if (isPlaceholder(m.value)) {
    if (prevReal) {
      io.err(
        `[${envName}] ${manifestPath} es un marcador pero la versión anterior tenía un manifiesto real: no se puede borrar un manifiesto publicado así.`,
      );
      return report({ ok: false, reason: 'placeholder_over_real' }, 1);
    }
    say(
      `[${envName}] ${manifestPath} es un marcador: todavía no hay manifiesto publicado. Nada que verificar.`,
    );
    return report({ ok: true, placeholder: true }, 0);
  }

  const k = readKeys(keysPath);
  if (k.error) {
    io.err(k.error);
    return 1;
  }
  let pinned = k.keys;
  if (prevReal && baseKeysValue !== null) {
    const bk = keysFromValue(baseKeysValue);
    if (bk.error) {
      io.err(bk.error);
      return 1;
    }
    if (bk.keys.size === 0) {
      io.err(
        `[${envName}] La base no tenía llaves fijadas pese a tener manifiesto real.`,
      );
      return report({ ok: false, reason: 'signatures' }, 1);
    }
    if (!sameKeys(bk.keys, k.keys)) {
      io.err(
        `[${envName}] LLAVES CAMBIADAS: revisión manual. ${keysPath} difiere de la base de confianza. ` +
          'La rotación se hace en dos pasos: primero un PR que solo cambie las llaves (con el manifiesto igual), que Miguel revisa y funde a conciencia; luego el manifiesto nuevo.',
      );
      return report({ ok: false, reason: 'keys_changed' }, 3);
    }
    pinned = bk.keys; // se verifica contra las llaves de la base
  }
  if (pinned.size === 0) {
    io.err(
      `[${envName}] ${keysPath} no tiene llaves públicas fijadas y ${manifestPath} sí trae un manifiesto.`,
    );
    return report({ ok: false, reason: 'signatures' }, 1);
  }

  let previous = null;
  let standalone = mode === 'daily';
  if (prevReal) {
    if (fromGit && prevText.text === m.text) {
      standalone = true; // idéntico a la base de confianza: ya verificado allí
    } else {
      const signed = isObj(prevText.value) ? prevText.value.signed : undefined;
      if (!validSigned(signed)) {
        io.err('El manifiesto anterior no parece válido.');
        return 1;
      }
      previous = signed;
    }
  }

  const r = verifyManifest(m.value, {
    publicKeys: pinned,
    environment: envName,
    previous,
    now,
    standalone,
    // Un candidato nuevo ya vencido no se acepta; la corrida diaria sí lo
    // reporta (exit 1 más abajo) sin tratarlo como candidato.
    rejectExpired: args.rejectExpired === true && !standalone,
  });
  if (!r.ok) {
    io.err(`[${envName}] MANIFIESTO NO VÁLIDO: ${r.reason}`);
    return report({ ok: false, reason: r.reason }, 1);
  }
  const json = { ok: true, expired: r.expired };
  if (args.json) return report(json, 0);

  const expires = Date.parse(r.manifest.expiresAt);
  const daysLeft = (expires - now.getTime()) / 86400000;
  say(
    `[${envName}] OK: versión ${r.manifest.version}, época ${r.manifest.epoch}, ` +
      `vence ${r.manifest.expiresAt} (${daysLeft.toFixed(1)} días)` +
      (standalone ? ' [sin cambios frente a la base / corrida diaria]' : '') +
      '.',
  );
  if (r.expired) {
    io.err(
      `[${envName}] El manifiesto ESTÁ VENCIDO. Firma y publica uno nuevo cuanto antes.`,
    );
    return 1;
  }
  if (minDays !== null && daysLeft < minDays) {
    io.err(
      `[${envName}] AVISO: al manifiesto le quedan ${daysLeft.toFixed(1)} días (mínimo ${minDays}). ` +
        'Hay que firmar y publicar uno nuevo (renovar cada 2 semanas).',
    );
    return 2;
  }
  return 0;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  process.exitCode = main(process.argv.slice(2));
}
