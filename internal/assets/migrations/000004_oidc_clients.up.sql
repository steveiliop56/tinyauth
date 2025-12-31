CREATE TABLE IF NOT EXISTS "oidc_clients" (
    "client_id" TEXT NOT NULL PRIMARY KEY UNIQUE,
    "client_secret" TEXT NOT NULL,
    "client_name" TEXT NOT NULL,
    "redirect_uris" TEXT NOT NULL,
    "grant_types" TEXT NOT NULL,
    "response_types" TEXT NOT NULL,
    "scopes" TEXT NOT NULL,
    "created_at" INTEGER NOT NULL,
    "updated_at" INTEGER NOT NULL
);

