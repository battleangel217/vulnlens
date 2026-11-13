import type { Chunk, CodeRule, RuleHit } from '../../types';
import { hit } from '../../types';
import { callsInLine, isSequenceLiteral, looksInterpolated } from '../python-syntax';

/* ------------------------------------------------------------------ *
 * Metadata shared by the rule definitions below
 * ------------------------------------------------------------------ */

const SQL = {
  id: 'py.sql-injection',
  cwe: 'CWE-89',
  title: 'SQL injection',
  severity: 'high',
} as const;

const CMD = {
  id: 'py.command-injection',
  cwe: 'CWE-78',
  title: 'OS command injection',
  severity: 'high',
} as const;

const TRAVERSAL = {
  id: 'py.path-traversal',
  cwe: 'CWE-22',
  title: 'Path traversal',
  severity: 'medium',
} as const;

const DESERIALIZATION = {
  id: 'py.insecure-deserialization',
  cwe: 'CWE-502',
  title: 'Insecure deserialization',
  severity: 'critical',
} as const;

const SECRETS = {
  id: 'py.hardcoded-secret',
  cwe: 'CWE-798',
  title: 'Hardcoded credential',
  severity: 'high',
} as const;

const CRYPTO = {
  id: 'py.weak-crypto',
  cwe: 'CWE-327',
  title: 'Broken or risky cryptographic algorithm',
  severity: 'medium',
} as const;

/* ------------------------------------------------------------------ *
 * CWE-89: SQL injection
 * ------------------------------------------------------------------ */

const SQL_CALLEE = /\b(?:execute|executemany|executescript|raw)\b/g;
const SQL_ASSIGNMENT_RE = /^[ \t]*(?:[A-Za-z_]\w*[ \t]*=[ \t]*)(.+?)[ \t]*(?:#.*)?$/;
const SQL_KEYWORD_RE = /\b(?:SELECT|INSERT[ \t]+INTO|UPDATE|DELETE[ \t]+FROM|REPLACE[ \t]+INTO)\b/i;

export const sqlInjectionRule: CodeRule = {
  ...SQL,
  run(chunk: Chunk): RuleHit[] {
    const hits: RuleHit[] = [];

    for (const { line, text } of chunk.lines) {
      for (const call of callsInLine(text, SQL_CALLEE)) {
        if (!call.firstArg) continue;
        if (looksInterpolated(call.firstArg)) {
          hits.push(
            hit(
              SQL,
              line,
              `Query passed to \`${call.callee}()\` is built from interpolated text. Use a parameterized query, e.g. \`${call.callee}("... WHERE id = %s", (value,))\`.`,
            ),
          );
        }
      }

      // Catches the split form: `query = f"SELECT ... {x}"` on its own line.
      const assignment = SQL_ASSIGNMENT_RE.exec(text);
      if (!assignment) continue;
      const rhs = assignment[1];
      if (!SQL_KEYWORD_RE.test(rhs)) continue;
      if (!looksInterpolated(rhs)) continue;
      if (/\b(?:execute|executemany|executescript|raw)\s*\(/.test(text)) continue;
      hits.push(
        hit(
          SQL,
          line,
          'SQL statement is assembled from interpolated text. Use bound parameters instead of f-strings, % formatting, or concatenation.',
        ),
      );
    }

    return hits;
  },
};

/* ------------------------------------------------------------------ *
 * CWE-78: OS command injection
 * ------------------------------------------------------------------ */

const SHELL_CALLEE = /\b(?:os\.system|os\.popen|os\.exec\w*|commands\.getoutput|commands\.getstatusoutput)\b/g;
const SUBPROCESS_CALLEE = /\b(?:subprocess\.(?:run|call|check_call|check_output|Popen)|asyncio\.create_subprocess_shell)\b/g;
const SHELL_TRUE_RE = /\bshell[ \t]*=[ \t]*True\b/;

export const commandInjectionRule: CodeRule = {
  ...CMD,
  run(chunk: Chunk): RuleHit[] {
    const hits: RuleHit[] = [];

    for (const { line, text } of chunk.lines) {
      for (const call of callsInLine(text, SHELL_CALLEE)) {
        if (!call.firstArg) continue;
        if (!looksInterpolated(call.firstArg)) continue;
        hits.push(
          hit(
            CMD,
            line,
            `Shell command passed to \`${call.callee}()\` is built from interpolated text, so untrusted input becomes shell syntax. Use an argument list with subprocess and avoid the shell.`,
          ),
        );
      }

      const shells = SHELL_TRUE_RE.test(text);
      for (const call of callsInLine(text, SUBPROCESS_CALLEE)) {
        if (!call.firstArg) continue;
        if (!shells) continue;
        if (isSequenceLiteral(call.firstArg)) continue;
        const interpolated = looksInterpolated(call.firstArg);
        hits.push(
          hit(
            CMD,
            line,
            interpolated
              ? `\`${call.callee}(..., shell=True)\` receives an interpolated command string. Pass an argument list and drop \`shell=True\`.`
              : `\`${call.callee}(..., shell=True)\` runs the command through a shell. Prefer an argument list with \`shell=False\`.`,
            line,
          ),
        );
      }
    }

    return hits;
  },
};

/* ------------------------------------------------------------------ *
 * CWE-22: Path traversal
 * ------------------------------------------------------------------ */

const TRAVERSAL_SINK = /\b(?:open|send_file|Path|os\.remove|os\.unlink|shutil\.copyfile|shutil\.move)\b/g;
const TAINT_RE =
  /(?:flask\.)?request\.(?:args|form|values|json|GET|POST|FILES|cookies|headers)|(?:^|[^\w.])input\s*\(|sys\.argv|os\.environ/;
const SANITIZER_RE = /\b(?:basename|realpath|abspath|secure_filename|normpath)\s*\(/;
const TAINT_ASSIGNMENT_RE = /^[ \t]*([A-Za-z_]\w*)[ \t]*=[ \t]*(.+)$/;

export const pathTraversalRule: CodeRule = {
  ...TRAVERSAL,
  run(chunk: Chunk): RuleHit[] {
    const hits: RuleHit[] = [];
    const tainted = new Map<string, number>();

    for (const { line, text } of chunk.lines) {
      // One-hop taint tracking keeps the rule quiet on ordinary file access
      // while still catching `name = request.args["f"]` followed by `open(name)`.
      const assignment = TAINT_ASSIGNMENT_RE.exec(text);
      if (assignment) {
        const [, name, rhs] = assignment;
        if (TAINT_RE.test(rhs)) {
          tainted.set(name, line);
        } else if (SANITIZER_RE.test(rhs)) {
          tainted.delete(name);
        } else if ([...tainted.keys()].some((source) => new RegExp(`\\b${source}\\b`).test(rhs))) {
          // Propagate through one intermediate variable, e.g.
          // `path = os.path.join(BASE, name)` where `name` came from the request.
          tainted.set(name, line);
        }
      }

      const sinks = callsInLine(text, TRAVERSAL_SINK);
      if (sinks.length === 0) continue;
      // `open(os.path.join(BASE, os.path.basename(x)))` is the recommended fix,
      // so do not report the line that already normalizes the path.
      if (SANITIZER_RE.test(text)) continue;

      const directlyTainted = TAINT_RE.test(text);
      const viaVariable = [...tainted.entries()].some(
        ([name, assignedLine]) =>
          assignedLine < line && new RegExp(`\\b${name}\\b`).test(text),
      );

      if (directlyTainted || viaVariable) {
        hits.push(
          hit(
            TRAVERSAL,
            line,
            `Filesystem path built from untrusted input reaches \`${sinks[0].callee}()\`. Resolve against a fixed base directory and reject anything outside it.`,
          ),
        );
        continue;
      }

      // Literal traversal segments, e.g. open("../../" + name).
      if (/["'][^"']*\.\.[^"']*["']\s*(?:\+|%|\.format)/.test(text)) {
        hits.push(
          hit(
            TRAVERSAL,
            line,
            'Path is assembled with a literal ".." segment. Normalize the resolved path and verify it stays inside the intended directory.',
          ),
        );
      }
    }

    return hits;
  },
};

/* ------------------------------------------------------------------ *
 * CWE-502: Insecure deserialization
 * ------------------------------------------------------------------ */

interface PatternRule {
  readonly re: RegExp;
  readonly severity: RuleHit['severity'];
  readonly allow?: RegExp;
  readonly label: string;
}

const DESERIALIZATION_PATTERNS: readonly PatternRule[] = [
  { re: /\bpickle\.(?:load|loads|Unpickler)\s*\(/, severity: 'critical', label: 'pickle' },
  { re: /\b(?:cPickle|dill|cloudpickle)\.(?:load|loads)\s*\(/, severity: 'critical', label: 'an unsafe pickle-compatible loader' },
  { re: /\bjsonpickle\.decode\s*\(/, severity: 'high', label: 'jsonpickle' },
  { re: /\byaml\.load\s*\(/, severity: 'high', allow: /SafeLoader|safe_load/, label: 'yaml.load' },
  { re: /\bmarshal\.loads?\s*\(/, severity: 'high', label: 'marshal' },
  { re: /\bjoblib\.load\s*\(/, severity: 'high', label: 'joblib' },
  { re: /\btorch\.load\s*\(/, severity: 'medium', allow: /weights_only\s*=\s*True/, label: 'torch.load' },
];

export const insecureDeserializationRule: CodeRule = {
  ...DESERIALIZATION,
  run(chunk: Chunk): RuleHit[] {
    const hits: RuleHit[] = [];

    for (const { line, text } of chunk.lines) {
      for (const pattern of DESERIALIZATION_PATTERNS) {
        if (!pattern.re.test(text)) continue;
        if (pattern.allow?.test(text)) continue;
        hits.push(
          hit(
            DESERIALIZATION,
            line,
            `${pattern.label} reconstructs arbitrary objects from untrusted bytes, which can lead to remote code execution. Use a data-only format such as JSON and validate the result.`,
          ),
        );
        break; // at most one deserialization finding per line
      }
    }

    return hits;
  },
};

/* ------------------------------------------------------------------ *
 * CWE-798: Hardcoded credentials
 * ------------------------------------------------------------------ */

const SECRET_NAME_RE =
  /(?:pass(?:word|wd)|pwd|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|token|credential)/i;

const ASSIGN_LITERAL_RE =
  /^[ \t]*(?:[A-Za-z_]\w*[ \t]*\.)*([A-Za-z_]\w*)[ \t]*=[ \t]*(["'])([^"'\n]*)\2[ \t]*(?:#.*)?$/;

const DICT_LITERAL_RE = /(["'])([A-Za-z_][\w-]*)\1[ \t]*:[ \t]*(["'])([^"'\n]*)\3/;

const AWS_KEY_RE = /\bAKIA[0-9A-Z]{16}\b/;
const PRIVATE_KEY_RE = /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/;
const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/;

function isPlaceholderValue(value: string): boolean {
  if (value.length < 4) return true;
  if (/^(?:https?|ftp):\/\//i.test(value)) return true;
  // `SECRET_FIELD = "client_secret"` names a config key, it does not leak one.
  if (/^[a-z][a-z0-9]*_[a-z0-9_]*$/.test(value)) return true;
  if (/^(?:\*+|x{3,}|\.{3,}|<[^>]*>|\$\{[^}]*\}|%\([^)]*\)s)$/i.test(value)) return true;
  return /^(?:changeme|change[_-]?me|placeholder|example|sample|dummy|testing?|todo|none|null|n\/a|fake[_-]?.*|your[_-].*|dev[_-].*)$/i.test(
    value,
  );
}

export const hardcodedSecretRule: CodeRule = {
  ...SECRETS,
  run(chunk: Chunk): RuleHit[] {
    const hits: RuleHit[] = [];

    for (const { line, text } of chunk.lines) {
      if (AWS_KEY_RE.test(text)) {
        hits.push(hit({ ...SECRETS, severity: 'critical' }, line, 'AWS access key ID is embedded in source. Move it to a secret manager or an environment variable.'));
        continue;
      }
      if (PRIVATE_KEY_RE.test(text)) {
        hits.push(hit({ ...SECRETS, severity: 'critical' }, line, 'Private key material is embedded in source. Remove it from the repository and rotate the key.'));
        continue;
      }
      if (JWT_RE.test(text)) {
        hits.push(hit(SECRETS, line, 'JSON Web Token is embedded in source. Tokens are credentials; load them at runtime instead.'));
        continue;
      }

      const assignment = ASSIGN_LITERAL_RE.exec(text);
      const dict = DICT_LITERAL_RE.exec(text);

      const candidate = assignment
        ? { name: assignment[1], value: assignment[3] }
        : dict
          ? { name: dict[2], value: dict[4] }
          : null;

      if (!candidate) continue;
      if (!SECRET_NAME_RE.test(candidate.name)) continue;
      if (isPlaceholderValue(candidate.value)) continue;

      hits.push(
        hit(
          SECRETS,
          line,
          `\`${candidate.name}\` is assigned a literal value. Load credentials from a secret store or environment variable so they never enter version control.`,
        ),
      );
    }

    return hits;
  },
};

/* ------------------------------------------------------------------ *
 * CWE-327: Weak cryptography
 * ------------------------------------------------------------------ */

const WEAK_CRYPTO_PATTERNS: readonly { re: RegExp; severity: RuleHit['severity']; message: string }[] = [
  {
    re: /\bhashlib\.(?:md5|sha1)\s*\(/i,
    severity: 'medium',
    message: 'MD5/SHA-1 are broken for security purposes. Use SHA-256 or stronger (and a password hash such as argon2 or bcrypt for passwords).',
  },
  {
    re: /\b(?:MD5|SHA)\.new\s*\(/,
    severity: 'medium',
    message: 'PyCryptodome `MD5.new`/`SHA.new` map to MD5/SHA-1. Use `SHA256.new()`.',
  },
  {
    re: /\b(?:DES3?|ARC4|RC4|Blowfish)\.new\s*\(/,
    severity: 'high',
    message: 'DES, RC4 and Blowfish are broken ciphers. Use AES-GCM or ChaCha20-Poly1305.',
  },
  {
    re: /\bssl\.PROTOCOL_(?:SSLv3|TLSv1|TLSv1_1)\b/,
    severity: 'high',
    message: 'Deprecated TLS protocol version. Use `ssl.PROTOCOL_TLS_CLIENT` with modern defaults.',
  },
  {
    re: /\b(?:ssl\.wrap_socket|SSLContext)\s*\([^)]*ssl_version\s*=\s*ssl\.PROTOCOL_(?:SSLv3|TLSv1|TLSv1_1)/,
    severity: 'high',
    message: 'Deprecated TLS protocol version is selected explicitly. Use the modern default context.',
  },
];

export const weakCryptoRule: CodeRule = {
  ...CRYPTO,
  run(chunk: Chunk): RuleHit[] {
    const hits: RuleHit[] = [];

    for (const { line, text } of chunk.lines) {
      for (const pattern of WEAK_CRYPTO_PATTERNS) {
        if (!pattern.re.test(text)) continue;
        hits.push(hit({ ...CRYPTO, severity: pattern.severity }, line, pattern.message));
        break;
      }
    }

    return hits;
  },
};

export const pythonRules: readonly CodeRule[] = [
  sqlInjectionRule,
  commandInjectionRule,
  pathTraversalRule,
  insecureDeserializationRule,
  hardcodedSecretRule,
  weakCryptoRule,
];

/** CWE id -> human title, used when the model reports a class no rule knows. */
export const CWE_TITLES: Readonly<Record<string, string>> = Object.fromEntries(
  pythonRules.map((rule) => [rule.cwe, rule.title]),
);
