-- name: CreateOidcCode :one
INSERT INTO "oidc_codes" (
    "sub",
    "code",
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
WHERE "code" = ?;

-- name: GetOidcCode :one
SELECT * FROM "oidc_codes"
WHERE "code" = ?;

-- name: CreateOidcToken :one
INSERT INTO "oidc_tokens" (
    "sub",
    "access_token",
    "scope",
    "client_id",
    "expires_at"
) VALUES (
    ?, ?, ?, ?, ?
)
RETURNING *;

-- name: DeleteOidcToken :exec
DELETE FROM "oidc_tokens"
WHERE "access_token" = ?;

-- name: GetOidcToken :one
SELECT * FROM "oidc_tokens"
WHERE "access_token" = ?;

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
