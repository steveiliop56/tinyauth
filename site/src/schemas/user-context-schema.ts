import { z } from "zod";

export const userContextSchema = z.object({
  isLoggedIn: z.boolean(),
});

export type UserContextSchemaType = z.infer<typeof userContextSchema>;
