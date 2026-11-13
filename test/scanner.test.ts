import { describe, expect, it } from 'vitest';
import { scanPython, summarize } from '../src/scan/scanner';
import type { RuleHit } from '../src/types';

function code(...lines: string[]): string {
  return lines.join('\n');
}

function cwes(findings: readonly RuleHit[]): string[] {
  return findings.map((finding) => finding.cwe);
}

describe('CWE-89 SQL injection', () => {
  it('flags f-strings, concatenation, % formatting and .format', () => {
    const cases = [
      'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
      'cursor.execute("SELECT * FROM users WHERE id = " + uid)',
      'cursor.execute("SELECT * FROM users WHERE id = %s" % uid)',
      'cursor.execute("SELECT * FROM users WHERE id = {}".format(uid))',
      'cursor.executemany(f"INSERT INTO t VALUES ({a})", rows)',
    ];

    for (const line of cases) {
      expect(cwes(scanPython(code(line))), line).toContain('CWE-89');
    }
  });

  it('leaves parameterized queries alone', () => {
    const safe = [
      'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))',
      "cursor.execute('SELECT * FROM users WHERE id = ?', (uid,))",
      'cursor.execute(QUERY, params)',
      'connection.execute("PRAGMA foreign_keys = ON")',
      'cursor.executemany("INSERT INTO t VALUES (%s)", rows)',
    ];

    for (const line of safe) {
      expect(cwes(scanPython(code(line))), line).not.toContain('CWE-89');
    }
  });

  it('catches a query built on its own line', () => {
    const findings = scanPython(
      code('query = f"SELECT * FROM users WHERE name = {name}"', 'cursor.execute(query)'),
    );
    expect(cwes(findings)).toContain('CWE-89');
  });
});

describe('CWE-78 command injection', () => {
  it('flags interpolated os.system and shell=True', () => {
    expect(cwes(scanPython(code('os.system("ping " + host)')))).toContain('CWE-78');
    expect(cwes(scanPython(code('os.popen(f"cat {path}")')))).toContain('CWE-78');
    expect(cwes(scanPython(code('subprocess.run(f"tar {target}", shell=True)')))).toContain(
      'CWE-78',
    );
  });

  it('leaves argument lists alone', () => {
    expect(cwes(scanPython(code('subprocess.run(["ls", "-l", path])')))).not.toContain('CWE-78');
    expect(cwes(scanPython(code('os.system("ls -la")')))).not.toContain('CWE-78');
  });
});

describe('CWE-22 path traversal', () => {
  it('flags untrusted input reaching a filesystem sink', () => {
    expect(cwes(scanPython(code('open(request.args["f"], "rb")')))).toContain('CWE-22');
  });

  it('follows a simple local assignment', () => {
    const findings = scanPython(
      code('name = request.args["name"]', 'handle = open(os.path.join("/srv", name), "rb")'),
    );
    expect(cwes(findings)).toContain('CWE-22');
  });

  it('leaves constants and sanitized paths alone', () => {
    const safe = [
      'open("config.json")',
      'open(os.path.join(BASE_DIR, "static", "index.html"))',
      'send_from_directory(BASE_DIR, name)',
      'open(os.path.join(BASE, os.path.basename(request.args["f"])))',
    ];
    for (const line of safe) {
      expect(cwes(scanPython(code(line))), line).not.toContain('CWE-22');
    }
  });
});

describe('CWE-502 insecure deserialization', () => {
  it('flags pickle and unsafe yaml/torch loading', () => {
    expect(cwes(scanPython(code('pickle.loads(blob)')))).toContain('CWE-502');
    expect(cwes(scanPython(code('yaml.load(stream)')))).toContain('CWE-502');
    expect(cwes(scanPython(code('torch.load(path)')))).toContain('CWE-502');
  });

  it('leaves safe loaders alone', () => {
    const safe = [
      'yaml.safe_load(stream)',
      'yaml.load(stream, Loader=yaml.SafeLoader)',
      'torch.load(path, weights_only=True)',
      'json.loads(blob)',
    ];
    for (const line of safe) {
      expect(cwes(scanPython(code(line))), line).not.toContain('CWE-502');
    }
  });
});

describe('CWE-798 hardcoded credentials', () => {
  it('flags literal secrets and well-known key formats', () => {
    expect(cwes(scanPython(code('password = "hunter2-prod"')))).toContain('CWE-798');
    expect(cwes(scanPython(code('self.api_key = "abcd1234efgh5678"')))).toContain('CWE-798');
    expect(cwes(scanPython(code('config = {"client_secret": "s3cr3tvalue"}')))).toContain(
      'CWE-798',
    );
    expect(cwes(scanPython(code('key = "AKIAIOSFODNN7EXAMPLE"')))).toContain('CWE-798');
  });

  it('leaves environment lookups and placeholders alone', () => {
    const safe = [
      'password = os.environ["DB_PASSWORD"]',
      'api_key = os.environ.get("API_KEY")',
      'token = "abc"',
      'API_KEY = "your-api-key-here"',
      'SECRET_NAME = "client_secret"',
      'if password == "hunter2-prod":',
    ];
    for (const line of safe) {
      expect(cwes(scanPython(code(line))), line).not.toContain('CWE-798');
    }
  });
});

describe('CWE-327 weak crypto', () => {
  it('flags md5, sha1 and deprecated TLS', () => {
    expect(cwes(scanPython(code('hashlib.md5(data).hexdigest()')))).toContain('CWE-327');
    expect(cwes(scanPython(code('hashlib.sha1(data)')))).toContain('CWE-327');
    expect(cwes(scanPython(code('context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)')))).toContain(
      'CWE-327',
    );
  });

  it('leaves sha256 and AES-GCM alone', () => {
    const safe = ['hashlib.sha256(data).digest()', 'AESGCM(key).encrypt(nonce, data, aad)'];
    for (const line of safe) {
      expect(cwes(scanPython(code(line))), line).not.toContain('CWE-327');
    }
  });
});

describe('scan behaviour', () => {
  it('reports one finding per rule and line for nested defs', () => {
    const source = code(
      'def outer():',
      '    def inner():',
      '        return hashlib.md5(b"x").hexdigest()',
      '    return inner()',
    );
    const findings = scanPython(source);
    expect(findings.filter((finding) => finding.cwe === 'CWE-327')).toHaveLength(1);
  });

  it('honours inline and above-line suppressions', () => {
    const inline = scanPython(code('password = "hunter2-prod"  # vuln-ignore'));
    expect(inline).toHaveLength(0);

    const above = scanPython(code('# vuln-ignore', 'password = "hunter2-prod"'));
    expect(above).toHaveLength(0);

    const qualified = scanPython(code('password = "hunter2-prod"  # vuln-ignore: CWE-89'));
    expect(cwes(qualified)).toContain('CWE-798');

    const targeted = scanPython(code('password = "hunter2-prod"  # vuln-ignore: CWE-798'));
    expect(targeted).toHaveLength(0);
  });

  it('filters by minimum severity', () => {
    const source = code('digest = hashlib.md5(b"x")', 'password = "hunter2-prod"');
    expect(scanPython(source, { minSeverity: 'high' }).map((f) => f.cwe)).toEqual(['CWE-798']);
  });

  it('sorts findings by line', () => {
    const source = code('password = "hunter2-prod"', 'digest = hashlib.md5(b"x")');
    const lines = scanPython(source).map((finding) => finding.line);
    expect(lines).toEqual([...lines].sort((a, b) => a - b));
  });

  it('summarizes by severity', () => {
    const findings = scanPython(
      code('password = "hunter2-prod"', 'pickle.loads(blob)', 'hashlib.md5(b"x")'),
    );
    const summary = summarize(findings);
    expect(summary.critical).toBe(1);
    expect(summary.high).toBe(1);
    expect(summary.medium).toBe(1);
  });
});
