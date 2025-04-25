import { z } from "zod";

export const appContextSchema = z.object({
  configuredProviders: z.array(z.string()),
  disableContinue: z.boolean(),
  autoOidcLogin: z.boolean(),
  title: z.string(),
  genericName: z.string(),
  domain: z.string(),
  forgotPasswordMessage: z.string(),
});

export type AppContextSchemaType = z.infer<typeof appContextSchema>;
