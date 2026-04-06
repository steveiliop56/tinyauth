ALTER TABLE "oidc_codes" ADD COLUMN "code_challenge" TEXT DEFAULT "";
ALTER TABLE "oidc_codes" ADD COLUMN "code_challenge_method" TEXT DEFAULT "";
