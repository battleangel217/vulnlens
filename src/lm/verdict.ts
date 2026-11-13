import { z } from 'zod';

const severitySchema = z.enum(['critical', 'high', 'medium', 'low']);

const confidenceSchema = z.preprocess((value) => {
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (trimmed.endsWith('%')) return Number.parseFloat(trimmed) / 100;
    const parsed = Number.parseFloat(trimmed);
    return Number.isFinite(parsed) ? parsed : value;
  }
  return value;
}, z.number().min(0).max(1));

const cweSchema = z
  .string()
  .regex(/^CWE-\d+$/i)
  .nullish()
  .transform((value) => (value ? value.toUpperCase() : null));

const lineSchema = z
  .preprocess(
    (value) => (typeof value === 'string' ? Number.parseInt(value, 10) : value),
    z.number().int().min(0).nullish(),
  )
  .transform((value) => (typeof value === 'number' && value > 0 ? value : null));

/**
 * The single contract between every backend and the UI.
 *
 * Zod strips unknown keys, so a chatty model returning extra fields still
 * produces a usable verdict. Anything that cannot be coerced fails loudly and
 * triggers one retry rather than silently rendering a bogus finding.
 */
export const verdictSchema = z.object({
  verdict: z.enum(['vulnerable', 'safe']),
  cwe: cweSchema,
  severity: severitySchema.nullish().transform((value) => value ?? null),
  confidence: confidenceSchema.default(0.5),
  /** 1-based line number relative to the snippet that was sent. */
  line: lineSchema,
  reason: z.string().min(1).max(4000),
  /** Complete replacement source for the analysed function, or null. */
  fix: z
    .string()
    .max(30000)
    .nullish()
    .transform((value) => (value && value.trim() ? value : null)),
});

export type LlmVerdict = z.infer<typeof verdictSchema>;

export type VerdictParse = { ok: true; verdict: LlmVerdict } | { ok: false; error: string };

/** Pull the first JSON object out of a reply, with or without code fences. */
export function extractJsonObject(text: string): string | null {
  const fenced = /```(?:json)?\s*([\s\S]*?)```/i.exec(text);
  const body = fenced ? fenced[1] : text;
  const start = body.indexOf('{');
  const end = body.lastIndexOf('}');
  if (start === -1 || end <= start) return null;
  return body.slice(start, end + 1);
}

export function parseVerdict(raw: string): VerdictParse {
  const json = extractJsonObject(raw);
  if (!json) return { ok: false, error: 'response contained no JSON object' };

  let value: unknown;
  try {
    value = JSON.parse(json);
  } catch (error) {
    return { ok: false, error: `invalid JSON: ${(error as Error).message}` };
  }

  const result = verdictSchema.safeParse(value);
  if (!result.success) {
    const issues = result.error.issues
      .map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('; ');
    return { ok: false, error: issues };
  }

  return { ok: true, verdict: result.data };
}

/** Strip markdown fences a model may have wrapped around a code fix. */
export function cleanFix(fix: string | null): string | undefined {
  if (!fix) return undefined;
  const trimmed = fix.trim();
  const fenced = /^```[a-zA-Z0-9_-]*\s*\n?([\s\S]*?)```$/.exec(trimmed);
  const body = (fenced ? fenced[1] : trimmed).trim();
  return body.length > 0 ? body : undefined;
}
