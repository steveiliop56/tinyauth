import { z } from "zod";

export const getOidcClientInfoScehma = z.object({
  name: z.string(),
});
