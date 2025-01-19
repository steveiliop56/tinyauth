import { z } from "zod";

export const userContextSchema = z.object({
  isLoggedIn: z.boolean(),
  username: z.string(),
});

export type UserContextSchemaType = z.infer<typeof userContextSchema>;
