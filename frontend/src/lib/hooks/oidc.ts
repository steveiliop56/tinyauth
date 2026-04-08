import { z } from "zod";

export const oidcParamsSchema = z.object({
  scope: z.string(),
  response_type: z.string(),
  client_id: z.string(),
  redirect_uri: z.string(),
  state: z.string().optional(),
  nonce: z.string().optional(),
  code_challenge: z.string().optional(),
  code_challenge_method: z.string().optional(),
  prompt: z.string().optional(),
});

export const useOIDCParams = (
  params: URLSearchParams,
): {
  values: z.infer<typeof oidcParamsSchema>;
  issues: string[];
  isOidc: boolean;
  compiled: string;
} => {
  const obj = Object.fromEntries(params.entries());
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
