import { z } from "zod";

export const getOidcClientInfoSchema = z.object({
  name: z.string(),
});
