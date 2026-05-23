-- Store device user codes in canonical uppercase form without separators.
-- The UI/API can still display and accept XXXX-XXXX for readability.
update public.device_tokens
set user_code = upper(replace(user_code, '-', ''))
where user_code <> upper(replace(user_code, '-', ''));

update public.device_tokens
set status = 'expired'
where status = 'pending'
  and expires_at < now();

with ranked as (
  select
    id,
    row_number() over (
      partition by user_code
      order by created_at desc, id desc
    ) as rn
  from public.device_tokens
  where status = 'pending'
)
update public.device_tokens d
set status = 'expired'
from ranked r
where d.id = r.id
  and r.rn > 1;

create unique index if not exists device_tokens_pending_user_code_unique
  on public.device_tokens(user_code)
  where status = 'pending';
