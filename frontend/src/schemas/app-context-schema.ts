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
  loginTitle: z.string().optional(),
  loginSubtitle: z.string().optional(),
  usernameTitle: z.string().optional(),
  passwordTitle: z.string().optional(),
  usernamePlaceholder: z.string().optional(),
  passwordPlaceholder: z.string().optional(),
  logo: z.string().optional(),
});

export type AppContextSchema = z.infer<typeof appContextSchema>;
