import { z } from "zod";

export const userContextSchema = z.object({
  isLoggedIn: z.boolean(),
  email: z.string(),
  oauth: z.boolean(),
  provider: z.string(),
});

export type UserContextSchemaType = z.infer<typeof userContextSchema>;
