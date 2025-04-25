import { z } from "zod";

export const userContextSchema = z.object({
  isLoggedIn: z.boolean(),
  username: z.string(),
  name: z.string(),
  email: z.string(),
  oauth: z.boolean(),
  provider: z.string(),
  totpPending: z.boolean(),
});

export type UserContextSchemaType = z.infer<typeof userContextSchema>;
