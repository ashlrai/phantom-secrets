const CONTENT_LENGTH = /^\d+$/;

export class RequestBodyError extends Error {
  constructor(
    readonly code: "invalid_body" | "body_too_large",
    readonly status: 400 | 413,
  ) {
    super(code);
    this.name = "RequestBodyError";
  }
}

function declaredLength(req: Request): number | null {
  const raw = req.headers.get("content-length");
  if (raw === null) return null;
  if (!CONTENT_LENGTH.test(raw)) {
    throw new RequestBodyError("invalid_body", 400);
  }

  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed)) {
    throw new RequestBodyError("body_too_large", 413);
  }
  return parsed;
}

export async function readBoundedText(
  req: Request,
  maxBytes: number,
): Promise<string> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new Error("maxBytes must be a positive safe integer");
  }

  const length = declaredLength(req);
  if (length !== null && length > maxBytes) {
    throw new RequestBodyError("body_too_large", 413);
  }
  if (!req.body) return "";

  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new RequestBodyError("body_too_large", 413);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }

  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    throw new RequestBodyError("invalid_body", 400);
  }
}

export async function readBoundedJsonObject<T extends object>(
  req: Request,
  maxBytes: number,
): Promise<T> {
  const text = await readBoundedText(req, maxBytes);
  try {
    const value: unknown = JSON.parse(text);
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("JSON body must be an object");
    }
    return value as T;
  } catch (error) {
    if (error instanceof RequestBodyError) throw error;
    throw new RequestBodyError("invalid_body", 400);
  }
}

export function requestBodyErrorResponse(error: unknown): Response {
  if (error instanceof RequestBodyError) {
    return Response.json({ error: error.code }, { status: error.status });
  }
  return Response.json({ error: "invalid_body" }, { status: 400 });
}
