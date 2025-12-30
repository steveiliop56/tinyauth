CREATE TABLE IF NOT EXISTS "oidc_authorization_codes" (
    "code" TEXT NOT NULL PRIMARY KEY,
    "client_id" TEXT NOT NULL,
    "redirect_uri" TEXT NOT NULL,
    "used" BOOLEAN NOT NULL DEFAULT 0,
    "expires_at" INTEGER NOT NULL,
    "created_at" INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS "idx_oidc_auth_codes_expires_at" ON "oidc_authorization_codes"("expires_at");

