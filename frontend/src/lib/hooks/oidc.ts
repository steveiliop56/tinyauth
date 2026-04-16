import { z } from "zod";

export const oidcParamsSchema = z.object({
  scope: z.string().min(1),
  response_type: z.string().min(1),
  client_id: z.string().min(1),
  redirect_uri: z.string().min(1),
  state: z.string().optional(),
  nonce: z.string().optional(),
  code_challenge: z.string().optional(),
  code_challenge_method: z.string().optional(),
});

function b64urlDecode(s: string): string {
  const base64 = s.replace(/-/g, "+").replace(/_/g, "/");
  return atob(base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "="));
}

function decodeRequestObject(jwt: string): Record<string, string> {
  try {
    // Must have exactly 3 parts: header, payload, signature
    const parts = jwt.split(".");
    if (parts.length !== 3) return {};

    // Header must specify "alg": "none" and signature must be empty string
    const header = JSON.parse(b64urlDecode(parts[0]));
    if (!header || typeof header !== "object" || header.alg !== "none" || parts[2] !== "") return {};

    const payload = JSON.parse(b64urlDecode(parts[1]));
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) return {};
    const result: Record<string, string> = {};
    for (const [k, v] of Object.entries(payload)) {
      if (typeof v === "string") result[k] = v;
    }
    return result;
  } catch {
    return {};
  }
}

export const useOIDCParams = (
  params: URLSearchParams,
): {
  values: z.infer<typeof oidcParamsSchema>;
  issues: string[];
  isOidc: boolean;
  compiled: string;
} => {
  const obj = Object.fromEntries(params.entries());

  // RFC 9101 / OIDC Core 6.1: if `request` param present, decode JWT payload
  // and merge claims over top-level params (JWT claims take precedence)
  const requestJwt = params.get("request");
  if (requestJwt) {
    const claims = decodeRequestObject(requestJwt);
    Object.assign(obj, claims);
  }

  const parsed = oidcParamsSchema.safeParse(obj);

  if (parsed.success) {
    return {
      values: parsed.data,
      issues: [],
      isOidc: true,
      compiled: new URLSearchParams(parsed.data).toString(),
    };
  }

  return {
    issues: parsed.error.issues.map((issue) => issue.path.toString()),
    values: {} as z.infer<typeof oidcParamsSchema>,
    isOidc: false,
    compiled: "",
  };
};
