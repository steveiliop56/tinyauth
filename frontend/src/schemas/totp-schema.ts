import { z } from "zod";

export const totpSchema = z.object({
  code: z.string(),
});

export type TotpSchema = z.infer<typeof totpSchema>;
