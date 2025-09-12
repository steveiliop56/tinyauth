import { z } from "zod";

export const providerSchema = z.object({
  id: z.string(),
  name: z.string(),
  oauth: z.boolean(),
});

export const appContextSchema = z.object({
  providers: z.array(providerSchema),
  title: z.string(),
  appUrl: z.string(),
  cookieDomain: z.string(),
  forgotPasswordMessage: z.string(),
  backgroundImage: z.string(),
  oauthAutoRedirect: z.string(),
});

export type AppContextSchema = z.infer<typeof appContextSchema>;
