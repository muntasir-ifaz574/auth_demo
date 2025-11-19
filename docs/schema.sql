-- Enable UUID generation
create extension if not exists "pgcrypto";

create or replace function set_updated_at()
returns trigger as $$
begin
    new.updated_at = now();
    return new;
end;
$$ language plpgsql;

create table if not exists users (
    id uuid primary key default gen_random_uuid(),
    email text not null unique,
    full_name text not null,
    phone_number text,
    password_hash text not null,
    email_verified_at timestamptz,
    last_login timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create table if not exists otp_codes (
    id uuid primary key default gen_random_uuid(),
    email text not null,
    code text not null,
    purpose text not null,
    payload jsonb,
    expires_at timestamptz not null,
    consumed_at timestamptz,
    created_at timestamptz not null default now()
);

create index if not exists idx_users_email on users (email);
create index if not exists idx_otp_email_purpose on otp_codes (email, purpose) where consumed_at is null;

create trigger trg_users_updated_at
before update on users
for each row execute function set_updated_at();
