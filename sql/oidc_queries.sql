-- name: CreateOidcCode :one
INSERT INTO "oidc_codes" (
    "sub",
    "code_hash",
    "scope",
    "redirect_uri",
    "client_id",
    "expires_at"
) VALUES (
    ?, ?, ?, ?, ?, ?
)
RETURNING *;

-- name: DeleteOidcCode :exec
DELETE FROM "oidc_codes"
WHERE "code_hash" = ?;

-- name: DeleteOidcCodeBySub :exec
DELETE FROM "oidc_codes"
WHERE "sub" = ?;

-- name: GetOidcCode :one
SELECT * FROM "oidc_codes"
WHERE "code_hash" = ?;

-- name: CreateOidcToken :one
INSERT INTO "oidc_tokens" (
    "sub",
    "access_token_hash",
    "refresh_token_hash",
    "scope",
    "client_id",
    "token_expires_at",
    "refresh_token_expires_at"
) VALUES (
    ?, ?, ?, ?, ?, ?, ?
)
RETURNING *;

-- name: UpdateOidcTokenByRefreshToken :one
UPDATE "oidc_tokens" SET
    "access_token_hash" = ?,
    "refresh_token_hash" = ?,
    "token_expires_at" = ?,
    "refresh_token_expires_at" = ?
WHERE "refresh_token_hash" = ?
RETURNING *;

-- name: DeleteOidcToken :exec
DELETE FROM "oidc_tokens"
WHERE "access_token_hash" = ?;

-- name: DeleteOidcTokenBySub :exec
DELETE FROM "oidc_tokens"
WHERE "sub" = ?;

-- name: GetOidcToken :one
SELECT * FROM "oidc_tokens"
WHERE "access_token_hash" = ?;

-- name: GetOidcTokenByRefreshToken :one
SELECT * FROM "oidc_tokens"
WHERE "refresh_token_hash" = ?;

-- name: CreateOidcUserInfo :one
INSERT INTO "oidc_userinfo" (
    "sub",
    "name",
    "preferred_username",
    "email",
    "groups",
    "updated_at"
) VALUES (
    ?, ?, ?, ?, ?, ?
)
RETURNING *;

-- name: DeleteOidcUserInfo :exec
DELETE FROM "oidc_userinfo"
WHERE "sub" = ?;

-- name: GetOidcUserInfo :one
SELECT * FROM "oidc_userinfo"
WHERE "sub" = ?;
