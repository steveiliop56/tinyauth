ALTER TABLE "sessions" ADD COLUMN "oauth_name" TEXT;

UPDATE
    "sessions"
SET
    "oauth_name" = "Generic"
WHERE
    "oauth_name" IS NULL AND "provider" IS NOT NULL;
