package repository

import (
	"context"
	"encoding/json"

	"github.com/redis/rueidis"
)

type RedisSessionRepository struct {
	c rueidis.Client
}

func NewRedisSessionRepository(c rueidis.Client) *RedisSessionRepository {
	return &RedisSessionRepository{
		c: c,
	}
}

func (r *RedisSessionRepository) GetSession(ctx context.Context, cookie string) (Session, error) {
	var out Session

	cmd := r.c.B().Get().Key(cookie).Build()
	res := r.c.Do(ctx, cmd)
	if err := res.Error(); err != nil {
		return out, err
	}

	raw, err := res.AsBytes()
	if err != nil {
		return out, err
	}

	if err := json.Unmarshal(raw, &out); err != nil {
		return out, err
	}

	return out, nil
}

func (r *RedisSessionRepository) CreateSession(
	ctx context.Context,
	params CreateSessionParams,
) (Session, error) {
	out := Session{
		UUID:        params.UUID,
		Email:       params.Email,
		Username:    params.Username,
		Name:        params.Name,
		Provider:    params.Provider,
		TotpPending: params.TotpPending,
		OAuthName:   params.OAuthName,
		OAuthGroups: params.OAuthGroups,
		OAuthSub:    params.OAuthSub,
		CreatedAt:   params.CreatedAt,
		Expiry:      params.Expiry,
	}

	raw, err := json.Marshal(out)
	if err != nil {
		return out, err
	}

	cmd := r.c.B().Set().Key(params.UUID).Value(string(raw)).Nx().Build()
	if err := r.c.Do(ctx, cmd).Error(); err != nil {
		return out, err
	}

	return out, nil
}

func (r *RedisSessionRepository) UpdateSession(
	ctx context.Context,
	params UpdateSessionParams,
) (Session, error) {
	session, err := r.GetSession(ctx, params.UUID)
	if err != nil {
		return session, err
	}

	session.UUID = params.UUID
	session.Email = params.Email
	session.Username = params.Username
	session.Name = params.Name
	session.Provider = params.Provider
	session.TotpPending = params.TotpPending
	session.OAuthName = params.OAuthName
	session.OAuthGroups = params.OAuthGroups
	session.OAuthSub = params.OAuthSub
	session.Expiry = params.Expiry

	raw, err := json.Marshal(session)
	if err != nil {
		return session, err
	}

	cmd := r.c.B().Set().Key(params.UUID).Value(string(raw)).Build()
	if err := r.c.Do(ctx, cmd).Error(); err != nil {
		return session, err
	}

	return session, nil
}

func (r *RedisSessionRepository) DeleteSession(ctx context.Context, cookie string) error {
	cmd := r.c.B().Del().Key(cookie).Build()
	if err := r.c.Do(ctx, cmd).Error(); err != nil {
		return err
	}
	return nil
}
