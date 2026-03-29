-- Phantom Pro — Initial Schema
-- Three tables: users, device_tokens, vault_blobs
-- All with Row Level Security enabled

-- ── users ─────────────────────────────────────────────────────────────────────
create table public.users (
  id            uuid primary key references auth.users(id) on delete cascade,
  github_login  text not null,
  email         text,
  stripe_customer_id text unique,
  plan          text not null default 'free',
  subscription_id text unique,
  plan_expires_at timestamptz,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now()
);

alter table public.users enable row level security;

create policy "users_read_own" on public.users
  for select using (id = auth.uid());
create policy "users_update_own" on public.users
  for update using (id = auth.uid());

-- ── device_tokens ─────────────────────────────────────────────────────────────
create table public.device_tokens (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid references public.users(id) on delete cascade,
  device_code   text unique not null,
  user_code     text not null,
  token_hash    text unique,
  status        text not null default 'pending',
  label         text default 'CLI Device',
  expires_at    timestamptz not null,
  created_at    timestamptz not null default now()
);

alter table public.device_tokens enable row level security;

create policy "device_tokens_read_own" on public.device_tokens
  for select using (user_id = auth.uid());

-- ── vault_blobs ───────────────────────────────────────────────────────────────
create table public.vault_blobs (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid references public.users(id) on delete cascade not null,
  project_id    text not null,
  encrypted_blob text not null,
  version       bigint not null default 1,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  unique(user_id, project_id)
);

alter table public.vault_blobs enable row level security;

create policy "vault_blobs_read_own" on public.vault_blobs
  for select using (user_id = auth.uid());
create policy "vault_blobs_insert_own" on public.vault_blobs
  for insert with check (user_id = auth.uid());
create policy "vault_blobs_update_own" on public.vault_blobs
  for update using (user_id = auth.uid());
create policy "vault_blobs_delete_own" on public.vault_blobs
  for delete using (user_id = auth.uid());

-- ── Indexes ───────────────────────────────────────────────────────────────────
create index on public.device_tokens(device_code);
create index on public.device_tokens(token_hash);
create index on public.device_tokens(user_code);
create index on public.vault_blobs(user_id, project_id);

-- ── updated_at trigger ────────────────────────────────────────────────────────
create or replace function update_updated_at()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end; $$;

create trigger users_updated_at before update on public.users
  for each row execute function update_updated_at();
create trigger vault_blobs_updated_at before update on public.vault_blobs
  for each row execute function update_updated_at();
