import { z } from "zod";

export const oidcParamsSchema = z.object({
  scope: z.string().nonempty(),
  response_type: z.string().nonempty(),
  client_id: z.string().nonempty(),
  redirect_uri: z.string().nonempty(),
  state: z.string().optional(),
  nonce: z.string().optional(),
  code_challenge: z.string().optional(),
  code_challenge_method: z.string().optional(),
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
