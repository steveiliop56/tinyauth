CREATE TABLE IF NOT EXISTS "oidc_keys" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "private_key" TEXT NOT NULL,
    "created_at" INTEGER NOT NULL,
    "updated_at" INTEGER NOT NULL
);

