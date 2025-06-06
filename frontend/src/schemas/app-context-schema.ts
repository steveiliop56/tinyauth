import { z } from "zod";

export const appContextSchema = z.object({
  configuredProviders: z.array(z.string()),
  disableContinue: z.boolean(),
  title: z.string(),
  genericName: z.string(),
  domain: z.string(),
  forgotPasswordMessage: z.string(),
  oauthAutoRedirect: z.enum(["none", "github", "google", "generic"]),
  backgroundImage: z.string(),
});

export type AppContextSchema = z.infer<typeof appContextSchema>;
