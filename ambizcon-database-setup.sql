
-- ===== migrations/0001_core.sql =====
-- Ambizcon Team Workspace — core schema, helper functions, RLS and audit triggers.
-- Run in order: 0001_core.sql, 0002_modules.sql (generated), 0003_motivations.sql (generated).

create extension if not exists "pgcrypto";

-- ───────── teams / roles ─────────
create table public.teams (
  id text primary key,                 -- 'admin' | 'development' | 'marketing' | 'creative'
  name text not null
);
insert into public.teams values ('admin','Admin'),('development','Development'),('marketing','Marketing'),('creative','Creative');

create table public.roles (
  id text primary key,                 -- 'admin' | 'lead' | 'member'
  description text not null
);
insert into public.roles values ('admin','Full access to every team'),('lead','Team lead'),('member','Team member');

-- ───────── profiles (the "users" table; auth.users holds credentials) ─────────
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null,
  email text not null unique,
  team text not null references public.teams(id) default 'development',
  role text not null references public.roles(id) default 'member',
  status text not null default 'active' check (status in ('active','disabled')),
  avatar_url text,
  last_login timestamptz,
  created_at timestamptz not null default now(),
  constraint admin_team_consistency check ((role = 'admin') = (team = 'admin'))
);
create index on public.profiles(team);

create table public.clients (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  created_at timestamptz not null default now()
);

-- ───────── helper functions (SECURITY DEFINER so policies never recurse into profiles RLS) ─────────
create or replace function public.my_team() returns text
language sql stable security definer set search_path = public as $$
  select team from public.profiles where id = auth.uid() and status = 'active'
$$;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select role = 'admin' and team = 'admin' from public.profiles where id = auth.uid() and status = 'active'), false)
$$;

create or replace function public.can_access_team(t text) returns boolean
language sql stable as $$ select public.is_admin() or public.my_team() = t $$;

-- Per-team, per-module access overrides set by an admin (cross-team collaboration). No row = default: a team has write access to
-- its own modules and none to other teams' modules.
create table public.module_permissions (
  team text not null check (team in ('development', 'marketing', 'creative')),
  module_key text not null,
  level text not null check (level in ('none', 'read', 'write')),
  primary key (team, module_key)
);
alter table public.module_permissions enable row level security;
create policy module_permissions_read on public.module_permissions for select to authenticated using (public.my_team() is not null);
create policy module_permissions_admin on public.module_permissions for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- plpgsql (late binding) so it can be used by policies in later migrations.
create or replace function public.module_level(p_team text, p_key text) returns text
language plpgsql stable security definer set search_path = public as $$
declare lvl text;
begin
  if public.is_admin() then return 'write'; end if;
  select level into lvl from public.module_permissions where team = public.my_team() and module_key = p_key;
  if lvl is not null then return lvl; end if;
  if public.my_team() = p_team then return 'write'; end if;
  return 'none';
end $$;

-- Configuration and permission changes are written to the audit trail (user_logs) by trigger, never by clients.
create or replace function public.log_config_change() returns trigger
language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid();
begin
  insert into public.user_logs(user_id, team, action, module_name, record_title, description)
    values (uid, 'admin', lower(tg_op), 'Configuration', tg_argv[0], initcap(lower(tg_op)) || ' ' || tg_argv[0]);
  return coalesce(new, old);
end $$;
create trigger module_permissions_audit after insert or update or delete on public.module_permissions for each row execute function public.log_config_change('module permission');

-- New auth user → profile row. Role/team default to the least-privileged values; admins promote via /api/admin/users.
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, name, email)
  values (new.id, coalesce(new.raw_user_meta_data->>'name', split_part(new.email,'@',1)), new.email);
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

-- Users may edit only their own non-privileged columns; role/team/status changes require an admin (or the service role).
create or replace function public.profiles_guard() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null or public.is_admin() then return new; end if;
  if new.role <> old.role or new.team <> old.team or new.status <> old.status or new.email <> old.email then
    raise exception 'Only an admin can change role, team, status or email';
  end if;
  return new;
end $$;
create trigger profiles_guard_trg before update on public.profiles for each row execute function public.profiles_guard();

create or replace function public.log_profile_change() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.role is distinct from old.role or new.team is distinct from old.team or new.status is distinct from old.status then
    insert into public.user_logs(user_id, team, action, module_name, record_title, description)
      values (auth.uid(), 'admin', 'permission', 'Employee accounts', new.name,
        'Changed ' || new.name || ': ' || old.team || '/' || old.role || '/' || old.status || ' → ' || new.team || '/' || new.role || '/' || new.status);
  end if;
  return new;
end $$;
create trigger profiles_audit after update on public.profiles for each row execute function public.log_profile_change();

create or replace function public.set_updated_at() returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end $$;

-- ───────── shared tables ─────────
create table public.activity_logs (
  id uuid primary key default gen_random_uuid(),
  module text not null,
  record_id uuid not null,
  record_title text,
  team text,
  user_id uuid references public.profiles(id) on delete set null,
  action text not null check (action in ('created','status','completed','assigned','output','updated','deleted')),
  detail text not null,
  created_at timestamptz not null default now()
);
create index on public.activity_logs(module, record_id, created_at);

create table public.user_logs (            -- development "User Log" module (read-only)
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.profiles(id) on delete set null,
  team text not null,
  action text not null,
  module_name text not null,
  record_title text,
  description text,
  ip text,
  created_at timestamptz not null default now()
);
create index on public.user_logs(created_at desc);

create table public.notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references public.profiles(id) on delete cascade,   -- one row per recipient
  title text not null,
  body text not null,
  kind text not null check (kind in ('expiry','due','overdue','creative','marketing','completed','admin','priority','check')),
  link text,
  read boolean not null default false,
  created_at timestamptz not null default now()
);
create index on public.notifications(user_id, created_at desc);

create table public.daily_motivations (
  id uuid primary key default gen_random_uuid(),
  message text not null,
  team text not null check (team in ('all','admin','development','marketing','creative')),
  date date,                           -- optional: pin a message to a specific day
  image text,                          -- character key (development|marketing|creative|admin)
  active boolean not null default true
);

create table public.motivation_shown (
  user_id uuid not null references public.profiles(id) on delete cascade,
  motivation_id uuid not null references public.daily_motivations(id) on delete cascade,
  shown_on date not null default current_date,
  primary key (user_id, shown_on)
);

-- ───────── notification helpers ─────────
create or replace function public.notify_team(t text, p_title text, p_body text, p_kind text, p_link text)
returns void language sql security definer set search_path = public as $$
  insert into public.notifications (user_id, title, body, kind, link)
  select id, p_title, p_body, p_kind, p_link from public.profiles where status = 'active' and (team = t or (t = 'admin' and role = 'admin'))
$$;

-- ───────── generic record trigger: activity timeline, user log, admin notifications ─────────
-- TG_ARGV: 0 module key, 1 team, 2 title column, 3 status column ('' if none), 4 completed-values (comma list), 5 href
create or replace function public.log_record_change() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  rec jsonb; old_rec jsonb; title text; ev text; detail text; uid uuid := auth.uid();
  ip text := coalesce(nullif(current_setting('request.headers', true), '')::json->>'x-forwarded-for', null);
  st_col text := tg_argv[3]; done_vals text[] := string_to_array(tg_argv[4], ',');
  team_name text := initcap(tg_argv[1]);
  module_title text := initcap(replace(tg_argv[0], '-', ' '));
begin
  if tg_op = 'DELETE' then rec := to_jsonb(old); else rec := to_jsonb(new); end if;
  title := coalesce(rec->>tg_argv[2], module_title);
  if tg_op = 'INSERT' then
    ev := 'created'; detail := 'Created ' || title;
    insert into public.activity_logs(module, record_id, record_title, team, user_id, action, detail) values (tg_argv[0], new.id, title, tg_argv[1], uid, ev, detail);
    if rec ? 'request_source' and coalesce(rec->>'request_source','') <> '' then
      perform public.notify_team('creative', 'New creative request', title || ' · from ' || (rec->>'request_source'), 'creative', tg_argv[5]);
      perform public.notify_team('admin', 'New creative request', title || ' requested', 'creative', tg_argv[5]);
    end if;
    if rec->>'assigned_to' is not null and (rec->>'assigned_to')::uuid is distinct from uid then
      insert into public.notifications(user_id, title, body, kind, link) values ((rec->>'assigned_to')::uuid, 'New task assigned', title || ' · ' || module_title, 'due', tg_argv[5]);
    end if;
  elsif tg_op = 'UPDATE' then
    old_rec := to_jsonb(old);
    if st_col <> '' and rec->>st_col is distinct from old_rec->>st_col then
      if (rec->>st_col) = any(done_vals) then
        ev := 'completed'; detail := 'Status changed to Completed';
        perform public.notify_team('admin', team_name || ' Team completed', team_name || ' Team completed: ' || title, 'completed', tg_argv[5]);
      else ev := 'status'; detail := 'Status changed to ' || coalesce(rec->>st_col, 'none'); end if;
      insert into public.activity_logs(module, record_id, record_title, team, user_id, action, detail) values (tg_argv[0], new.id, title, tg_argv[1], uid, ev, detail);
    end if;
    if rec->>'assigned_to' is distinct from old_rec->>'assigned_to' and rec->>'assigned_to' is not null then
      insert into public.activity_logs(module, record_id, record_title, team, user_id, action, detail)
        values (tg_argv[0], new.id, title, tg_argv[1], uid, 'assigned', 'Assigned to ' || coalesce((select name from public.profiles where id = (rec->>'assigned_to')::uuid), 'someone'));
      if (rec->>'assigned_to')::uuid is distinct from uid then
        insert into public.notifications(user_id, title, body, kind, link) values ((rec->>'assigned_to')::uuid, 'Task assigned to you', title || ' · ' || module_title, 'due', tg_argv[5]);
      end if;
    end if;
    -- creative requests: tell the requesting marketer when the work is submitted, approved or completed
    if rec ? 'requested_by' and rec->>'requested_by' is not null and (rec->>'requested_by')::uuid is distinct from uid
       and st_col <> '' and rec->>st_col is distinct from old_rec->>st_col then
      if rec->>st_col = 'Submitted for Review' then
        insert into public.notifications(user_id, title, body, kind, link) values ((rec->>'requested_by')::uuid, 'Creative submitted for review', title, 'creative', tg_argv[5]);
      elsif rec->>st_col = 'Approved' then
        insert into public.notifications(user_id, title, body, kind, link) values ((rec->>'requested_by')::uuid, 'Creative approved', title, 'creative', tg_argv[5]);
      elsif rec->>st_col = any(done_vals) then
        insert into public.notifications(user_id, title, body, kind, link) values ((rec->>'requested_by')::uuid, 'Creative completed', title, 'creative', tg_argv[5]);
      end if;
    end if;
    if coalesce(rec->>'output_link','') <> '' and coalesce(old_rec->>'output_link','') = '' then
      insert into public.activity_logs(module, record_id, record_title, team, user_id, action, detail) values (tg_argv[0], new.id, title, tg_argv[1], uid, 'output', 'Output link added');
    end if;
    if (rec - 'updated_at' - 'updated_by' - st_col - 'assigned_to') is distinct from (old_rec - 'updated_at' - 'updated_by' - st_col - 'assigned_to') then
      insert into public.activity_logs(module, record_id, record_title, team, user_id, action, detail) values (tg_argv[0], new.id, title, tg_argv[1], uid, 'updated', 'Record details updated');
    end if;
    ev := coalesce(ev, 'updated'); detail := coalesce(detail, 'Updated');
  else
    ev := 'deleted'; detail := 'Deleted ' || title;
    insert into public.activity_logs(module, record_id, record_title, team, user_id, action, detail) values (tg_argv[0], old.id, title, tg_argv[1], uid, ev, detail);
  end if;
  insert into public.user_logs(user_id, team, action, module_name, record_title, description, ip)
    values (uid, tg_argv[1], ev, module_title, title, detail, ip);
  return coalesce(new, old);
end $$;

-- ───────── RLS: shared tables ─────────
alter table public.teams enable row level security;
alter table public.roles enable row level security;
alter table public.profiles enable row level security;
alter table public.clients enable row level security;
alter table public.activity_logs enable row level security;
alter table public.user_logs enable row level security;
alter table public.notifications enable row level security;
alter table public.daily_motivations enable row level security;
alter table public.motivation_shown enable row level security;

create policy teams_read on public.teams for select to authenticated using (true);
create policy roles_read on public.roles for select to authenticated using (true);

create policy profiles_read on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_admin() or team = public.my_team());
create policy profiles_update_self on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());
create policy profiles_admin_all on public.profiles for all to authenticated using (public.is_admin()) with check (public.is_admin());

create policy clients_read on public.clients for select to authenticated using (public.my_team() is not null);
create policy clients_write on public.clients for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- timeline entries are visible to whoever can see the team that owns the module (checked via module → team map in code); keep simple: same team or admin
create policy activity_read on public.activity_logs for select to authenticated using (public.can_access_team(team));
create policy user_logs_read on public.user_logs for select to authenticated using (public.can_access_team(team));
-- no insert/update/delete policies: only SECURITY DEFINER triggers write these tables.

create policy notifications_own on public.notifications for select to authenticated using (user_id = auth.uid());
create policy notifications_mark_read on public.notifications for update to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy motivations_read on public.daily_motivations for select to authenticated using (public.my_team() is not null);
create policy motivations_admin on public.daily_motivations for all to authenticated using (public.is_admin()) with check (public.is_admin());
create policy shown_own on public.motivation_shown for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

-- ───────── realtime + storage ─────────
alter publication supabase_realtime add table public.notifications;
insert into storage.buckets (id, name, public) values ('thumbnails','thumbnails', true) on conflict do nothing;
create policy thumbs_upload on storage.objects for insert to authenticated with check (bucket_id = 'thumbnails' and public.my_team() is not null);
create policy thumbs_read on storage.objects for select using (bucket_id = 'thumbnails');

-- ===== migrations/0002_modules.sql =====
-- GENERATED by scripts/gen-sql.ts from src/lib/modules.ts — do not edit by hand.

-- Workflow rules shared by every module table (mirrors src/lib/modulerules.ts).
-- TG_ARGV: 0 'review' for modules with a reviewer workflow, 1 status column, 2 completed values (comma list), 3 '1' if the table has completion_date
create or replace function public.module_rules() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  uid uuid := auth.uid(); adm boolean := public.is_admin();
  n jsonb := to_jsonb(new); o jsonb := case when tg_op = 'UPDATE' then to_jsonb(old) else '{}'::jsonb end;
  review boolean := tg_argv[0] = 'review'; st text := tg_argv[1]; done text[] := string_to_array(tg_argv[2], ','); has_cd boolean := tg_argv[3] = '1';
  patch jsonb := '{}'::jsonb; final_status text; final_review text; is_done boolean;
begin
  if uid is null then return new; end if;     -- service role / seed scripts
  if review then
    if tg_op = 'UPDATE' and n->>'review_status' is distinct from o->>'review_status' and n->>'review_status' in ('Approved', 'Changes requested') then
      if not adm and (n->>'reviewer') is distinct from uid::text then raise exception 'Only the assigned reviewer (or an admin) can approve or request changes'; end if;
      if not adm and (n->>'assigned_to') = uid::text then raise exception 'You cannot review your own work'; end if;
      if n->>'review_status' = 'Approved' then patch := patch || jsonb_build_object('status', case when n->>'status' = 'Completed' then 'Completed' else 'Approved' end);
      else patch := patch || jsonb_build_object('status', 'Changes Requested'); end if;
    elsif tg_op = 'UPDATE' and n->>'status' is distinct from o->>'status' then
      if n->>'status' = 'Submitted for Review' then
        if n->>'reviewer' is not null then patch := patch || jsonb_build_object('review_status', 'In review'); end if;
      elsif n->>'status' = 'Approved' and n->>'review_status' is distinct from 'Approved' then
        raise exception 'Work can only be Approved by its reviewer';
      end if;
    end if;
    final_status := coalesce(patch->>'status', n->>'status');
    final_review := coalesce(patch->>'review_status', n->>'review_status');
    if final_status = 'Completed' and (tg_op = 'INSERT' or o->>'status' is distinct from 'Completed') and n->>'reviewer' is not null and final_review is distinct from 'Approved' then
      raise exception 'This needs reviewer approval before it can be completed';
    end if;
  end if;
  if has_cd then
    is_done := coalesce(patch->>st, n->>st) = any(done);
    patch := patch || jsonb_build_object('completion_date', case when is_done then to_jsonb(coalesce(n->>'completion_date', current_date::text)) else 'null'::jsonb end);
  end if;
  if patch <> '{}'::jsonb then new := jsonb_populate_record(new, patch); end if;
  return new;
end $$;

create table public.website_backups (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  website text,
  website_url text,
  backup_date date,
  backup_type text check (backup_type is null or backup_type in ('Full', 'Database', 'Files', 'Other')),
  backup_link text,
  verification text check (verification is null or verification in ('Unverified', 'Verified', 'Failed')),
  verified_by uuid references public.profiles(id) on delete set null,
  link_verified_on date,
  next_backup_date date,
  assigned_to uuid references public.profiles(id) on delete set null,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.website_backups(created_at desc);
alter table public.website_backups enable row level security;
create trigger website_backups_updated before update on public.website_backups for each row execute function public.set_updated_at();
create trigger website_backups_audit after insert or update or delete on public.website_backups
  for each row execute function public.log_record_change('backups', 'development', 'website', 'verification', 'Verified', '/development/backups');
create policy website_backups_select on public.website_backups for select to authenticated using (public.module_level('development', 'backups') in ('read', 'write'));
create policy website_backups_update on public.website_backups for update to authenticated using (public.module_level('development', 'backups') = 'write') with check (public.module_level('development', 'backups') = 'write');
create policy website_backups_delete on public.website_backups for delete to authenticated using (public.module_level('development', 'backups') = 'write');
create policy website_backups_insert on public.website_backups for insert to authenticated with check (public.module_level('development', 'backups') = 'write');
alter publication supabase_realtime add table public.website_backups;

create table public.website_performance (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  website text,
  report_month text check (report_month is null or report_month in ('January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December')),
  report_year numeric,
  sessions numeric,
  users numeric,
  page_views numeric,
  engagement_rate numeric,
  conversions numeric,
  organic_clicks numeric,
  organic_impressions numeric,
  avg_position numeric,
  desktop_score numeric,
  mobile_score numeric,
  seo_score numeric,
  best_practices_score numeric,
  accessibility_score numeric,
  data_source text check (data_source is null or data_source in ('Manual entry', 'GA4 export', 'Search Console export', 'Other report')),
  report_link text,
  assigned_to uuid references public.profiles(id) on delete set null,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.website_performance(created_at desc);
alter table public.website_performance enable row level security;
create trigger website_performance_updated before update on public.website_performance for each row execute function public.set_updated_at();
create trigger website_performance_audit after insert or update or delete on public.website_performance
  for each row execute function public.log_record_change('performance', 'development', 'website', '', 'Completed', '/development/website-performance');
create policy website_performance_select on public.website_performance for select to authenticated using (public.module_level('development', 'performance') in ('read', 'write'));
create policy website_performance_update on public.website_performance for update to authenticated using (public.module_level('development', 'performance') = 'write') with check (public.module_level('development', 'performance') = 'write');
create policy website_performance_delete on public.website_performance for delete to authenticated using (public.module_level('development', 'performance') = 'write');
create policy website_performance_insert on public.website_performance for insert to authenticated with check (public.module_level('development', 'performance') = 'write');
alter publication supabase_realtime add table public.website_performance;

create table public.seo_updates (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  website text,
  page_url text,
  seo_type text check (seo_type is null or seo_type in ('On-Page', 'Technical', 'Off-Page', 'Local SEO', 'Schema', 'Indexing')),
  title text,
  keyword text,
  meta_title text,
  meta_description text,
  heading_updates text,
  image_alt text,
  internal_links text,
  schema_changes text,
  indexing_status text check (indexing_status is null or indexing_status in ('Not submitted', 'Submitted', 'Indexed', 'Not indexed')),
  date_assigned date,
  completion_date date,
  output_link text,
  assigned_to uuid references public.profiles(id) on delete set null,
  due_date date,
  priority text check (priority is null or priority in ('Low', 'Medium', 'High', 'Urgent')),
  status text check (status is null or status in ('Pending', 'In Progress', 'Completed', 'On Hold', 'Overdue', 'Cancelled')),
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.seo_updates(created_at desc);
alter table public.seo_updates enable row level security;
create trigger seo_updates_updated before update on public.seo_updates for each row execute function public.set_updated_at();
create trigger seo_updates_rules before insert or update on public.seo_updates
  for each row execute function public.module_rules('', 'status', 'Completed', '1');
create trigger seo_updates_audit after insert or update or delete on public.seo_updates
  for each row execute function public.log_record_change('seo', 'development', 'title', 'status', 'Completed', '/development/seo-updates');
create policy seo_updates_select on public.seo_updates for select to authenticated using (public.module_level('development', 'seo') in ('read', 'write'));
create policy seo_updates_update on public.seo_updates for update to authenticated using (public.module_level('development', 'seo') = 'write') with check (public.module_level('development', 'seo') = 'write');
create policy seo_updates_delete on public.seo_updates for delete to authenticated using (public.module_level('development', 'seo') = 'write');
create policy seo_updates_insert on public.seo_updates for insert to authenticated with check (public.module_level('development', 'seo') = 'write');
alter publication supabase_realtime add table public.seo_updates;

create table public.blog_updates (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  website text,
  blog_title text,
  blog_url text,
  category text,
  assigned_to uuid references public.profiles(id) on delete set null,
  date_assigned date,
  draft_date date,
  published_date date,
  blog_status text check (blog_status is null or blog_status in ('Planned', 'Drafting', 'Review', 'Published', 'Cancelled')),
  publish_verified boolean not null default false,
  output_link text,
  due_date date,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.blog_updates(created_at desc);
alter table public.blog_updates enable row level security;
create trigger blog_updates_updated before update on public.blog_updates for each row execute function public.set_updated_at();
create trigger blog_updates_audit after insert or update or delete on public.blog_updates
  for each row execute function public.log_record_change('blogs', 'development', 'blog_title', 'blog_status', 'Published', '/development/blogs');
create policy blog_updates_select on public.blog_updates for select to authenticated using (public.module_level('development', 'blogs') in ('read', 'write'));
create policy blog_updates_update on public.blog_updates for update to authenticated using (public.module_level('development', 'blogs') = 'write') with check (public.module_level('development', 'blogs') = 'write');
create policy blog_updates_delete on public.blog_updates for delete to authenticated using (public.module_level('development', 'blogs') = 'write');
create policy blog_updates_insert on public.blog_updates for insert to authenticated with check (public.module_level('development', 'blogs') = 'write');
alter publication supabase_realtime add table public.blog_updates;

create table public.website_expiry (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  domain text,
  website text,
  registrar text,
  expiry_date date,
  hosting_expiry date,
  hosting_provider text,
  assigned_to uuid references public.profiles(id) on delete set null,
  due_date date,
  status text check (status is null or status in ('Pending', 'In Progress', 'Completed', 'On Hold', 'Overdue', 'Cancelled')),
  date_confidence text check (date_confidence is null or date_confidence in ('Confirmed', 'Estimated', 'Unknown')),
  renewal_url text,
  last_verified date,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.website_expiry(created_at desc);
alter table public.website_expiry enable row level security;
create trigger website_expiry_updated before update on public.website_expiry for each row execute function public.set_updated_at();
create trigger website_expiry_audit after insert or update or delete on public.website_expiry
  for each row execute function public.log_record_change('website-expiry', 'development', 'domain', 'status', 'Completed', '/development/domain-expiry');
create policy website_expiry_select on public.website_expiry for select to authenticated using (public.module_level('development', 'website-expiry') in ('read', 'write'));
create policy website_expiry_update on public.website_expiry for update to authenticated using (public.module_level('development', 'website-expiry') = 'write') with check (public.module_level('development', 'website-expiry') = 'write');
create policy website_expiry_delete on public.website_expiry for delete to authenticated using (public.module_level('development', 'website-expiry') = 'write');
create policy website_expiry_insert on public.website_expiry for insert to authenticated with check (public.module_level('development', 'website-expiry') = 'write');
alter publication supabase_realtime add table public.website_expiry;

create table public.ssl_expiry (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  website text,
  ssl_provider text check (ssl_provider is null or ssl_provider in ('Let''s Encrypt', 'Cloudflare', 'GoDaddy', 'DigiCert', 'Sectigo')),
  ssl_expiry_date date,
  certificate_status text check (certificate_status is null or certificate_status in ('Valid', 'Expiring soon', 'Expired', 'Unknown')),
  last_checked date,
  check_method text check (check_method is null or check_method in ('Manual verification', 'Automated check')),
  assigned_to uuid references public.profiles(id) on delete set null,
  due_date date,
  status text check (status is null or status in ('Pending', 'In Progress', 'Completed', 'On Hold', 'Overdue', 'Cancelled')),
  date_confidence text check (date_confidence is null or date_confidence in ('Confirmed', 'Estimated', 'Unknown')),
  renewal_url text,
  last_verified date,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.ssl_expiry(created_at desc);
alter table public.ssl_expiry enable row level security;
create trigger ssl_expiry_updated before update on public.ssl_expiry for each row execute function public.set_updated_at();
create trigger ssl_expiry_audit after insert or update or delete on public.ssl_expiry
  for each row execute function public.log_record_change('ssl-expiry', 'development', 'website', 'status', 'Completed', '/development/ssl-expiry');
create policy ssl_expiry_select on public.ssl_expiry for select to authenticated using (public.module_level('development', 'ssl-expiry') in ('read', 'write'));
create policy ssl_expiry_update on public.ssl_expiry for update to authenticated using (public.module_level('development', 'ssl-expiry') = 'write') with check (public.module_level('development', 'ssl-expiry') = 'write');
create policy ssl_expiry_delete on public.ssl_expiry for delete to authenticated using (public.module_level('development', 'ssl-expiry') = 'write');
create policy ssl_expiry_insert on public.ssl_expiry for insert to authenticated with check (public.module_level('development', 'ssl-expiry') = 'write');
alter publication supabase_realtime add table public.ssl_expiry;

create table public.daily_website_checks (
  id uuid primary key default gen_random_uuid(),
  website text,
  client_id uuid references public.clients(id) on delete set null,
  check_date date,
  assigned_to uuid references public.profiles(id) on delete set null,
  loads text check (loads is null or loads in ('Pass', 'Warning', 'Fail')),
  homepage text check (homepage is null or homepage in ('Pass', 'Warning', 'Fail')),
  pages text check (pages is null or pages in ('Pass', 'Warning', 'Fail')),
  forms text check (forms is null or forms in ('Pass', 'Warning', 'Fail')),
  mobile text check (mobile is null or mobile in ('Pass', 'Warning', 'Fail')),
  ssl text check (ssl is null or ssl in ('Pass', 'Warning', 'Fail')),
  links text check (links is null or links in ('Pass', 'Warning', 'Fail')),
  speed text check (speed is null or speed in ('Pass', 'Warning', 'Fail')),
  backup text check (backup is null or backup in ('Pass', 'Warning', 'Fail')),
  security text check (security is null or security in ('Pass', 'Warning', 'Fail')),
  issue_description text,
  follow_up text,
  evidence_link text,
  reviewed_by uuid references public.profiles(id) on delete set null,
  priority text check (priority is null or priority in ('Low', 'Medium', 'High', 'Urgent')),
  status text check (status is null or status in ('Pending', 'In Progress', 'Completed', 'On Hold', 'Overdue', 'Cancelled')),
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.daily_website_checks(created_at desc);
alter table public.daily_website_checks enable row level security;
create trigger daily_website_checks_updated before update on public.daily_website_checks for each row execute function public.set_updated_at();
create trigger daily_website_checks_audit after insert or update or delete on public.daily_website_checks
  for each row execute function public.log_record_change('daily-check', 'development', 'website', 'status', 'Completed', '/development/daily-checks');
create policy daily_website_checks_select on public.daily_website_checks for select to authenticated using (public.module_level('development', 'daily-check') in ('read', 'write'));
create policy daily_website_checks_update on public.daily_website_checks for update to authenticated using (public.module_level('development', 'daily-check') = 'write') with check (public.module_level('development', 'daily-check') = 'write');
create policy daily_website_checks_delete on public.daily_website_checks for delete to authenticated using (public.module_level('development', 'daily-check') = 'write');
create policy daily_website_checks_insert on public.daily_website_checks for insert to authenticated with check (public.module_level('development', 'daily-check') = 'write');
alter publication supabase_realtime add table public.daily_website_checks;

create table public.dev_tools_expiry (
  id uuid primary key default gen_random_uuid(),
  tool_name text,
  vendor text,
  tool_type text check (tool_type is null or tool_type in ('Hosting', 'Plugin', 'Theme', 'Design', 'Monitoring', 'Security', 'Productivity')),
  license_type text check (license_type is null or license_type in ('Subscription', 'Annual', 'Monthly', 'One-time', 'Open source')),
  purchase_date date,
  expiry_date date,
  cost numeric,
  account_ref text,
  assigned_to uuid references public.profiles(id) on delete set null,
  due_date date,
  status text check (status is null or status in ('Pending', 'In Progress', 'Completed', 'On Hold', 'Overdue', 'Cancelled')),
  date_confidence text check (date_confidence is null or date_confidence in ('Confirmed', 'Estimated', 'Unknown')),
  renewal_url text,
  last_verified date,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.dev_tools_expiry(created_at desc);
alter table public.dev_tools_expiry enable row level security;
create trigger dev_tools_expiry_updated before update on public.dev_tools_expiry for each row execute function public.set_updated_at();
create trigger dev_tools_expiry_audit after insert or update or delete on public.dev_tools_expiry
  for each row execute function public.log_record_change('tools-expiry', 'development', 'tool_name', 'status', 'Completed', '/development/tools-expiry');
create policy dev_tools_expiry_select on public.dev_tools_expiry for select to authenticated using (public.module_level('development', 'tools-expiry') in ('read', 'write'));
create policy dev_tools_expiry_update on public.dev_tools_expiry for update to authenticated using (public.module_level('development', 'tools-expiry') = 'write') with check (public.module_level('development', 'tools-expiry') = 'write');
create policy dev_tools_expiry_delete on public.dev_tools_expiry for delete to authenticated using (public.module_level('development', 'tools-expiry') = 'write');
create policy dev_tools_expiry_insert on public.dev_tools_expiry for insert to authenticated with check (public.module_level('development', 'tools-expiry') = 'write');
alter publication supabase_realtime add table public.dev_tools_expiry;

create table public.smtp_tools_expiry (
  id uuid primary key default gen_random_uuid(),
  smtp_tool text,
  provider text,
  client_id uuid references public.clients(id) on delete set null,
  website text,
  plan text,
  expiry_date date,
  cost numeric,
  billing_cycle text check (billing_cycle is null or billing_cycle in ('Monthly', 'Yearly')),
  last_email_test date,
  delivery_status text check (delivery_status is null or delivery_status in ('Delivered', 'Delayed', 'Failing', 'Not tested')),
  assigned_to uuid references public.profiles(id) on delete set null,
  due_date date,
  status text check (status is null or status in ('Pending', 'In Progress', 'Completed', 'On Hold', 'Overdue', 'Cancelled')),
  date_confidence text check (date_confidence is null or date_confidence in ('Confirmed', 'Estimated', 'Unknown')),
  renewal_url text,
  last_verified date,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.smtp_tools_expiry(created_at desc);
alter table public.smtp_tools_expiry enable row level security;
create trigger smtp_tools_expiry_updated before update on public.smtp_tools_expiry for each row execute function public.set_updated_at();
create trigger smtp_tools_expiry_audit after insert or update or delete on public.smtp_tools_expiry
  for each row execute function public.log_record_change('smtp-expiry', 'development', 'smtp_tool', 'status', 'Completed', '/development/smtp-expiry');
create policy smtp_tools_expiry_select on public.smtp_tools_expiry for select to authenticated using (public.module_level('development', 'smtp-expiry') in ('read', 'write'));
create policy smtp_tools_expiry_update on public.smtp_tools_expiry for update to authenticated using (public.module_level('development', 'smtp-expiry') = 'write') with check (public.module_level('development', 'smtp-expiry') = 'write');
create policy smtp_tools_expiry_delete on public.smtp_tools_expiry for delete to authenticated using (public.module_level('development', 'smtp-expiry') = 'write');
create policy smtp_tools_expiry_insert on public.smtp_tools_expiry for insert to authenticated with check (public.module_level('development', 'smtp-expiry') = 'write');
alter publication supabase_realtime add table public.smtp_tools_expiry;

create table public.google_tracking (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  website text,
  ads_account_ref text,
  analytics_property_ref text,
  gtm_container_ref text,
  account_setup boolean not null default false,
  tag_installed boolean not null default false,
  events_verified boolean not null default false,
  conversion_tested boolean not null default false,
  tracking_status text check (tracking_status is null or tracking_status in ('Working', 'Partial', 'Not Working', 'Not Set')),
  conversion_status text check (conversion_status is null or conversion_status in ('Working', 'Partial', 'Not Working', 'Not Set')),
  last_verified date,
  report_link text,
  issues text,
  assigned_to uuid references public.profiles(id) on delete set null,
  due_date date,
  priority text check (priority is null or priority in ('Low', 'Medium', 'High', 'Urgent')),
  status text check (status is null or status in ('Pending', 'In Progress', 'Completed', 'On Hold', 'Overdue', 'Cancelled')),
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.google_tracking(created_at desc);
alter table public.google_tracking enable row level security;
create trigger google_tracking_updated before update on public.google_tracking for each row execute function public.set_updated_at();
create trigger google_tracking_audit after insert or update or delete on public.google_tracking
  for each row execute function public.log_record_change('google-tracker', 'development', 'website', 'status', 'Completed', '/development/google-tracker');
create policy google_tracking_select on public.google_tracking for select to authenticated using (public.module_level('development', 'google-tracker') in ('read', 'write'));
create policy google_tracking_update on public.google_tracking for update to authenticated using (public.module_level('development', 'google-tracker') = 'write') with check (public.module_level('development', 'google-tracker') = 'write');
create policy google_tracking_delete on public.google_tracking for delete to authenticated using (public.module_level('development', 'google-tracker') = 'write');
create policy google_tracking_insert on public.google_tracking for insert to authenticated with check (public.module_level('development', 'google-tracker') = 'write');
alter publication supabase_realtime add table public.google_tracking;

create table public.domain_access (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  domain text,
  registrar text,
  expiry_date date,
  account_owner text,
  access_email text,
  access_status text check (access_status is null or access_status in ('Full Access', 'Partial', 'No Access', 'Requested')),
  two_factor text check (two_factor is null or two_factor in ('Enabled', 'Not enabled', 'Unknown')),
  vault_ref text,
  assigned_to uuid references public.profiles(id) on delete set null,
  due_date date,
  status text check (status is null or status in ('Pending', 'In Progress', 'Completed', 'On Hold', 'Overdue', 'Cancelled')),
  date_confidence text check (date_confidence is null or date_confidence in ('Confirmed', 'Estimated', 'Unknown')),
  renewal_url text,
  last_verified date,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.domain_access(created_at desc);
alter table public.domain_access enable row level security;
create trigger domain_access_updated before update on public.domain_access for each row execute function public.set_updated_at();
create trigger domain_access_audit after insert or update or delete on public.domain_access
  for each row execute function public.log_record_change('domain-access', 'development', 'domain', 'status', 'Completed', '/development/domain-access');
create policy domain_access_select on public.domain_access for select to authenticated using (public.module_level('development', 'domain-access') in ('read', 'write'));
create policy domain_access_update on public.domain_access for update to authenticated using (public.module_level('development', 'domain-access') = 'write') with check (public.module_level('development', 'domain-access') = 'write');
create policy domain_access_delete on public.domain_access for delete to authenticated using (public.module_level('development', 'domain-access') = 'write');
create policy domain_access_insert on public.domain_access for insert to authenticated with check (public.module_level('development', 'domain-access') = 'write');
alter publication supabase_realtime add table public.domain_access;

create table public.spot_calendar (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  campaign text,
  content_title text,
  content_type text check (content_type is null or content_type in ('Blog', 'Post', 'Reel', 'Story', 'Carousel', 'Video', 'Mailer')),
  platform text check (platform is null or platform in ('Instagram', 'Facebook', 'LinkedIn', 'YouTube', 'X', 'Google Business', 'Website', 'Email')),
  assigned_to uuid references public.profiles(id) on delete set null,
  content_date date,
  publish_time time,
  calendar_status text check (calendar_status is null or calendar_status in ('Planned', 'Brief Ready', 'Design in Progress', 'Review', 'Approved', 'Scheduled', 'Published', 'Cancelled')),
  creative_link text,
  caption text,
  output_link text,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.spot_calendar(created_at desc);
alter table public.spot_calendar enable row level security;
create trigger spot_calendar_updated before update on public.spot_calendar for each row execute function public.set_updated_at();
create trigger spot_calendar_audit after insert or update or delete on public.spot_calendar
  for each row execute function public.log_record_change('spot-calendar', 'marketing', 'content_title', 'calendar_status', 'Published', '/marketing/content-calendar');
create policy spot_calendar_select on public.spot_calendar for select to authenticated using (public.module_level('marketing', 'spot-calendar') in ('read', 'write'));
create policy spot_calendar_update on public.spot_calendar for update to authenticated using (public.module_level('marketing', 'spot-calendar') = 'write') with check (public.module_level('marketing', 'spot-calendar') = 'write');
create policy spot_calendar_delete on public.spot_calendar for delete to authenticated using (public.module_level('marketing', 'spot-calendar') = 'write');
create policy spot_calendar_insert on public.spot_calendar for insert to authenticated with check (public.module_level('marketing', 'spot-calendar') = 'write');
alter publication supabase_realtime add table public.spot_calendar;

create table public.mailer_reports (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  campaign_name text,
  subject text,
  send_date date,
  provider text,
  report_url text,
  metrics_source text check (metrics_source is null or metrics_source in ('Provider report (imported by hand)', 'Entered by hand')),
  total_recipients numeric,
  delivered numeric,
  bounced numeric,
  opened numeric,
  unique_opens numeric,
  clicked numeric,
  unique_clicks numeric,
  unsubscribed numeric,
  spam_complaints numeric,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.mailer_reports(created_at desc);
alter table public.mailer_reports enable row level security;
create trigger mailer_reports_updated before update on public.mailer_reports for each row execute function public.set_updated_at();
create trigger mailer_reports_audit after insert or update or delete on public.mailer_reports
  for each row execute function public.log_record_change('mailer-reports', 'marketing', 'campaign_name', '', 'Completed', '/marketing/mailer-reports');
create policy mailer_reports_select on public.mailer_reports for select to authenticated using (public.module_level('marketing', 'mailer-reports') in ('read', 'write'));
create policy mailer_reports_update on public.mailer_reports for update to authenticated using (public.module_level('marketing', 'mailer-reports') = 'write') with check (public.module_level('marketing', 'mailer-reports') = 'write');
create policy mailer_reports_delete on public.mailer_reports for delete to authenticated using (public.module_level('marketing', 'mailer-reports') = 'write');
create policy mailer_reports_insert on public.mailer_reports for insert to authenticated with check (public.module_level('marketing', 'mailer-reports') = 'write');
alter publication supabase_realtime add table public.mailer_reports;

create table public.google_ads_logs (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  campaign text,
  log_date date,
  spend numeric,
  impressions numeric,
  clicks numeric,
  conversions numeric,
  conversion_value numeric,
  change_made text,
  issue_identified text,
  next_action text,
  assigned_to uuid references public.profiles(id) on delete set null,
  report_link text,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.google_ads_logs(created_at desc);
alter table public.google_ads_logs enable row level security;
create trigger google_ads_logs_updated before update on public.google_ads_logs for each row execute function public.set_updated_at();
create trigger google_ads_logs_audit after insert or update or delete on public.google_ads_logs
  for each row execute function public.log_record_change('google-ads', 'marketing', 'campaign', '', 'Completed', '/marketing/google-ads-logs');
create policy google_ads_logs_select on public.google_ads_logs for select to authenticated using (public.module_level('marketing', 'google-ads') in ('read', 'write'));
create policy google_ads_logs_update on public.google_ads_logs for update to authenticated using (public.module_level('marketing', 'google-ads') = 'write') with check (public.module_level('marketing', 'google-ads') = 'write');
create policy google_ads_logs_delete on public.google_ads_logs for delete to authenticated using (public.module_level('marketing', 'google-ads') = 'write');
create policy google_ads_logs_insert on public.google_ads_logs for insert to authenticated with check (public.module_level('marketing', 'google-ads') = 'write');
alter publication supabase_realtime add table public.google_ads_logs;

create table public.google_analytics (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  website text,
  report_date date,
  sessions numeric,
  users numeric,
  new_users numeric,
  page_views numeric,
  engagement_rate numeric,
  conversions numeric,
  traffic_source text check (traffic_source is null or traffic_source in ('Organic', 'Direct', 'Social', 'Referral', 'Paid', 'Email')),
  campaign text,
  report_link text,
  assigned_to uuid references public.profiles(id) on delete set null,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.google_analytics(created_at desc);
alter table public.google_analytics enable row level security;
create trigger google_analytics_updated before update on public.google_analytics for each row execute function public.set_updated_at();
create trigger google_analytics_audit after insert or update or delete on public.google_analytics
  for each row execute function public.log_record_change('google-analytics', 'marketing', 'website', '', 'Completed', '/marketing/google-analytics');
create policy google_analytics_select on public.google_analytics for select to authenticated using (public.module_level('marketing', 'google-analytics') in ('read', 'write'));
create policy google_analytics_update on public.google_analytics for update to authenticated using (public.module_level('marketing', 'google-analytics') = 'write') with check (public.module_level('marketing', 'google-analytics') = 'write');
create policy google_analytics_delete on public.google_analytics for delete to authenticated using (public.module_level('marketing', 'google-analytics') = 'write');
create policy google_analytics_insert on public.google_analytics for insert to authenticated with check (public.module_level('marketing', 'google-analytics') = 'write');
alter publication supabase_realtime add table public.google_analytics;

create table public.google_client_setup (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  website text,
  analytics boolean not null default false,
  search_console boolean not null default false,
  business_profile boolean not null default false,
  gtm boolean not null default false,
  ads boolean not null default false,
  conversion_tracking boolean not null default false,
  account_owner text,
  access_verification text check (access_verification is null or access_verification in ('Unverified', 'Verified', 'Access issue')),
  setup_date date,
  assigned_to uuid references public.profiles(id) on delete set null,
  outstanding_tasks text,
  evidence_link text,
  status text check (status is null or status in ('Pending', 'In Progress', 'Completed', 'On Hold', 'Overdue', 'Cancelled')),
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.google_client_setup(created_at desc);
alter table public.google_client_setup enable row level security;
create trigger google_client_setup_updated before update on public.google_client_setup for each row execute function public.set_updated_at();
create trigger google_client_setup_audit after insert or update or delete on public.google_client_setup
  for each row execute function public.log_record_change('google-setup', 'marketing', 'website', 'status', 'Completed', '/marketing/google-client-setup');
create policy google_client_setup_select on public.google_client_setup for select to authenticated using (public.module_level('marketing', 'google-setup') in ('read', 'write'));
create policy google_client_setup_update on public.google_client_setup for update to authenticated using (public.module_level('marketing', 'google-setup') = 'write') with check (public.module_level('marketing', 'google-setup') = 'write');
create policy google_client_setup_delete on public.google_client_setup for delete to authenticated using (public.module_level('marketing', 'google-setup') = 'write');
create policy google_client_setup_insert on public.google_client_setup for insert to authenticated with check (public.module_level('marketing', 'google-setup') = 'write');
alter publication supabase_realtime add table public.google_client_setup;

create table public.mailer_scheduler (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  campaign text,
  campaign_goal text,
  audience text,
  subject_line text,
  content text,
  scheduled_date date,
  scheduled_time time,
  assigned_to uuid references public.profiles(id) on delete set null,
  image_requirement text,
  image_ref text,
  output_link text,
  review_status text check (review_status is null or review_status in ('Not reviewed', 'In review', 'Approved', 'Changes requested')),
  campaign_status text check (campaign_status is null or campaign_status in ('Draft', 'Ready', 'Scheduled', 'Sent', 'Cancelled')),
  report_link text,
  creative_task_ref text,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.mailer_scheduler(created_at desc);
alter table public.mailer_scheduler enable row level security;
create trigger mailer_scheduler_updated before update on public.mailer_scheduler for each row execute function public.set_updated_at();
create trigger mailer_scheduler_audit after insert or update or delete on public.mailer_scheduler
  for each row execute function public.log_record_change('mailer-scheduler', 'marketing', 'campaign', 'campaign_status', 'Sent', '/marketing/mailer-scheduler');
create policy mailer_scheduler_select on public.mailer_scheduler for select to authenticated using (public.module_level('marketing', 'mailer-scheduler') in ('read', 'write'));
create policy mailer_scheduler_update on public.mailer_scheduler for update to authenticated using (public.module_level('marketing', 'mailer-scheduler') = 'write') with check (public.module_level('marketing', 'mailer-scheduler') = 'write');
create policy mailer_scheduler_delete on public.mailer_scheduler for delete to authenticated using (public.module_level('marketing', 'mailer-scheduler') = 'write');
create policy mailer_scheduler_insert on public.mailer_scheduler for insert to authenticated with check (public.module_level('marketing', 'mailer-scheduler') = 'write');
alter publication supabase_realtime add table public.mailer_scheduler;

create table public.community_groups (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  location text,
  group_name text,
  platform text check (platform is null or platform in ('Facebook', 'LinkedIn', 'Instagram', 'WhatsApp', 'Telegram', 'Reddit')),
  group_link text,
  group_type text check (group_type is null or group_type in ('Public', 'Private')),
  members numeric,
  request_status text check (request_status is null or request_status in ('Not requested', 'Pending', 'Accepted', 'Rejected')),
  request_date date,
  last_checked date,
  assigned_to uuid references public.profiles(id) on delete set null,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.community_groups(created_at desc);
alter table public.community_groups enable row level security;
create trigger community_groups_updated before update on public.community_groups for each row execute function public.set_updated_at();
create trigger community_groups_audit after insert or update or delete on public.community_groups
  for each row execute function public.log_record_change('community-groups', 'marketing', 'group_name', 'request_status', 'Accepted', '/marketing/community-groups');
create policy community_groups_select on public.community_groups for select to authenticated using (public.module_level('marketing', 'community-groups') in ('read', 'write'));
create policy community_groups_update on public.community_groups for update to authenticated using (public.module_level('marketing', 'community-groups') = 'write') with check (public.module_level('marketing', 'community-groups') = 'write');
create policy community_groups_delete on public.community_groups for delete to authenticated using (public.module_level('marketing', 'community-groups') = 'write');
create policy community_groups_insert on public.community_groups for insert to authenticated with check (public.module_level('marketing', 'community-groups') = 'write');
alter publication supabase_realtime add table public.community_groups;

create table public.community_tracker (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  community text,
  post_name text,
  topic text,
  format text check (format is null or format in ('Image', 'Text', 'Video', 'Other')),
  post_link text,
  post_date date,
  assigned_to uuid references public.profiles(id) on delete set null,
  engagement_notes text,
  output_link text,
  status text check (status is null or status in ('Pending', 'In Progress', 'Completed', 'On Hold', 'Overdue', 'Cancelled')),
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.community_tracker(created_at desc);
alter table public.community_tracker enable row level security;
create trigger community_tracker_updated before update on public.community_tracker for each row execute function public.set_updated_at();
create trigger community_tracker_audit after insert or update or delete on public.community_tracker
  for each row execute function public.log_record_change('community-tracker', 'marketing', 'post_name', 'status', 'Completed', '/marketing/community-tracker');
create policy community_tracker_select on public.community_tracker for select to authenticated using (public.module_level('marketing', 'community-tracker') in ('read', 'write'));
create policy community_tracker_update on public.community_tracker for update to authenticated using (public.module_level('marketing', 'community-tracker') = 'write') with check (public.module_level('marketing', 'community-tracker') = 'write');
create policy community_tracker_delete on public.community_tracker for delete to authenticated using (public.module_level('marketing', 'community-tracker') = 'write');
create policy community_tracker_insert on public.community_tracker for insert to authenticated with check (public.module_level('marketing', 'community-tracker') = 'write');
alter publication supabase_realtime add table public.community_tracker;

create table public.blog_youtube_updates (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  content_title text,
  content_type text check (content_type is null or content_type in ('Blog', 'YouTube')),
  channel_site text,
  content_url text,
  assigned_to uuid references public.profiles(id) on delete set null,
  date_assigned date,
  publication_date date,
  output_link text,
  due_date date,
  status text check (status is null or status in ('Pending', 'In Progress', 'Completed', 'On Hold', 'Overdue', 'Cancelled')),
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.blog_youtube_updates(created_at desc);
alter table public.blog_youtube_updates enable row level security;
create trigger blog_youtube_updates_updated before update on public.blog_youtube_updates for each row execute function public.set_updated_at();
create trigger blog_youtube_updates_audit after insert or update or delete on public.blog_youtube_updates
  for each row execute function public.log_record_change('blog-youtube', 'marketing', 'content_title', 'status', 'Completed', '/marketing/blog-youtube');
create policy blog_youtube_updates_select on public.blog_youtube_updates for select to authenticated using (public.module_level('marketing', 'blog-youtube') in ('read', 'write'));
create policy blog_youtube_updates_update on public.blog_youtube_updates for update to authenticated using (public.module_level('marketing', 'blog-youtube') = 'write') with check (public.module_level('marketing', 'blog-youtube') = 'write');
create policy blog_youtube_updates_delete on public.blog_youtube_updates for delete to authenticated using (public.module_level('marketing', 'blog-youtube') = 'write');
create policy blog_youtube_updates_insert on public.blog_youtube_updates for insert to authenticated with check (public.module_level('marketing', 'blog-youtube') = 'write');
alter publication supabase_realtime add table public.blog_youtube_updates;

create table public.monthly_blog_targets (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  year numeric,
  month text check (month is null or month in ('January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December')),
  target numeric,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.monthly_blog_targets(created_at desc);
alter table public.monthly_blog_targets enable row level security;
create trigger monthly_blog_targets_updated before update on public.monthly_blog_targets for each row execute function public.set_updated_at();
create trigger monthly_blog_targets_audit after insert or update or delete on public.monthly_blog_targets
  for each row execute function public.log_record_change('blog-targets', 'marketing', 'remark', '', 'Completed', '/marketing/blog-targets');
create policy monthly_blog_targets_select on public.monthly_blog_targets for select to authenticated using (public.module_level('marketing', 'blog-targets') in ('read', 'write'));
create policy monthly_blog_targets_update on public.monthly_blog_targets for update to authenticated using (public.module_level('marketing', 'blog-targets') = 'write') with check (public.module_level('marketing', 'blog-targets') = 'write');
create policy monthly_blog_targets_delete on public.monthly_blog_targets for delete to authenticated using (public.module_level('marketing', 'blog-targets') = 'write');
create policy monthly_blog_targets_insert on public.monthly_blog_targets for insert to authenticated with check (public.module_level('marketing', 'blog-targets') = 'write');
alter publication supabase_realtime add table public.monthly_blog_targets;

create table public.youtube_channels (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  channel_name text,
  channel_url text,
  channel_id text,
  channel_created boolean not null default false,
  creation_date date,
  assigned_to uuid references public.profiles(id) on delete set null,
  branding_status text check (branding_status is null or branding_status in ('Not started', 'In progress', 'Done')),
  logo_banner_status text check (logo_banner_status is null or logo_banner_status in ('Not started', 'In progress', 'Done')),
  description_status text check (description_status is null or description_status in ('Not started', 'In progress', 'Done')),
  first_video boolean not null default false,
  last_upload date,
  setup_status text check (setup_status is null or setup_status in ('Not started', 'In progress', 'Complete', 'Needs update')),
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.youtube_channels(created_at desc);
alter table public.youtube_channels enable row level security;
create trigger youtube_channels_updated before update on public.youtube_channels for each row execute function public.set_updated_at();
create trigger youtube_channels_audit after insert or update or delete on public.youtube_channels
  for each row execute function public.log_record_change('youtube', 'marketing', 'channel_name', 'setup_status', 'Complete', '/marketing/youtube-channels');
create policy youtube_channels_select on public.youtube_channels for select to authenticated using (public.module_level('marketing', 'youtube') in ('read', 'write'));
create policy youtube_channels_update on public.youtube_channels for update to authenticated using (public.module_level('marketing', 'youtube') = 'write') with check (public.module_level('marketing', 'youtube') = 'write');
create policy youtube_channels_delete on public.youtube_channels for delete to authenticated using (public.module_level('marketing', 'youtube') = 'write');
create policy youtube_channels_insert on public.youtube_channels for insert to authenticated with check (public.module_level('marketing', 'youtube') = 'write');
alter publication supabase_realtime add table public.youtube_channels;

create table public.creative_web_requirements (
  id uuid primary key default gen_random_uuid(),
  task text,
  client_id uuid references public.clients(id) on delete set null,
  description text,
  assigned_to uuid references public.profiles(id) on delete set null,
  priority text check (priority is null or priority in ('Low', 'Medium', 'High', 'Urgent')),
  status text check (status is null or status in ('New', 'Assigned', 'In Progress', 'On Hold', 'Submitted for Review', 'Changes Requested', 'Approved', 'Completed')),
  date_assigned date,
  due_date date,
  output_link text,
  thumbnail text,
  reviewer uuid references public.profiles(id) on delete set null,
  review_status text check (review_status is null or review_status in ('Not reviewed', 'In review', 'Approved', 'Changes requested')),
  completion_date date,
  category text,
  brief text,
  dimensions text,
  request_source text,
  requested_by uuid references public.profiles(id) on delete set null,
  source_ref text,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.creative_web_requirements(created_at desc);
alter table public.creative_web_requirements enable row level security;
create trigger creative_web_requirements_updated before update on public.creative_web_requirements for each row execute function public.set_updated_at();
create trigger creative_web_requirements_rules before insert or update on public.creative_web_requirements
  for each row execute function public.module_rules('review', 'status', 'Completed', '1');
create trigger creative_web_requirements_audit after insert or update or delete on public.creative_web_requirements
  for each row execute function public.log_record_change('web', 'creative', 'task', 'status', 'Completed', '/creative/adhoc/web-requirements');
create policy creative_web_requirements_select on public.creative_web_requirements for select to authenticated using (public.module_level('creative', 'web') in ('read', 'write'));
create policy creative_web_requirements_update on public.creative_web_requirements for update to authenticated using (public.module_level('creative', 'web') = 'write') with check (public.module_level('creative', 'web') = 'write');
create policy creative_web_requirements_delete on public.creative_web_requirements for delete to authenticated using (public.module_level('creative', 'web') = 'write');
create policy creative_web_requirements_insert on public.creative_web_requirements for insert to authenticated with check (public.module_level('creative', 'web') = 'write' or (public.my_team() = 'marketing' and request_source is not null));
create policy creative_web_requirements_select_requester on public.creative_web_requirements for select to authenticated using (requested_by = auth.uid());
alter publication supabase_realtime add table public.creative_web_requirements;

create table public.creative_videos (
  id uuid primary key default gen_random_uuid(),
  task text,
  client_id uuid references public.clients(id) on delete set null,
  description text,
  assigned_to uuid references public.profiles(id) on delete set null,
  priority text check (priority is null or priority in ('Low', 'Medium', 'High', 'Urgent')),
  status text check (status is null or status in ('New', 'Assigned', 'In Progress', 'On Hold', 'Submitted for Review', 'Changes Requested', 'Approved', 'Completed')),
  date_assigned date,
  due_date date,
  output_link text,
  thumbnail text,
  reviewer uuid references public.profiles(id) on delete set null,
  review_status text check (review_status is null or review_status in ('Not reviewed', 'In review', 'Approved', 'Changes requested')),
  completion_date date,
  category text,
  brief text,
  dimensions text,
  request_source text,
  requested_by uuid references public.profiles(id) on delete set null,
  source_ref text,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.creative_videos(created_at desc);
alter table public.creative_videos enable row level security;
create trigger creative_videos_updated before update on public.creative_videos for each row execute function public.set_updated_at();
create trigger creative_videos_rules before insert or update on public.creative_videos
  for each row execute function public.module_rules('review', 'status', 'Completed', '1');
create trigger creative_videos_audit after insert or update or delete on public.creative_videos
  for each row execute function public.log_record_change('videos', 'creative', 'task', 'status', 'Completed', '/creative/adhoc/videos');
create policy creative_videos_select on public.creative_videos for select to authenticated using (public.module_level('creative', 'videos') in ('read', 'write'));
create policy creative_videos_update on public.creative_videos for update to authenticated using (public.module_level('creative', 'videos') = 'write') with check (public.module_level('creative', 'videos') = 'write');
create policy creative_videos_delete on public.creative_videos for delete to authenticated using (public.module_level('creative', 'videos') = 'write');
create policy creative_videos_insert on public.creative_videos for insert to authenticated with check (public.module_level('creative', 'videos') = 'write' or (public.my_team() = 'marketing' and request_source is not null));
create policy creative_videos_select_requester on public.creative_videos for select to authenticated using (requested_by = auth.uid());
alter publication supabase_realtime add table public.creative_videos;

create table public.creative_artworks (
  id uuid primary key default gen_random_uuid(),
  task text,
  client_id uuid references public.clients(id) on delete set null,
  description text,
  assigned_to uuid references public.profiles(id) on delete set null,
  priority text check (priority is null or priority in ('Low', 'Medium', 'High', 'Urgent')),
  status text check (status is null or status in ('New', 'Assigned', 'In Progress', 'On Hold', 'Submitted for Review', 'Changes Requested', 'Approved', 'Completed')),
  date_assigned date,
  due_date date,
  output_link text,
  thumbnail text,
  reviewer uuid references public.profiles(id) on delete set null,
  review_status text check (review_status is null or review_status in ('Not reviewed', 'In review', 'Approved', 'Changes requested')),
  completion_date date,
  category text,
  brief text,
  dimensions text,
  request_source text,
  requested_by uuid references public.profiles(id) on delete set null,
  source_ref text,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.creative_artworks(created_at desc);
alter table public.creative_artworks enable row level security;
create trigger creative_artworks_updated before update on public.creative_artworks for each row execute function public.set_updated_at();
create trigger creative_artworks_rules before insert or update on public.creative_artworks
  for each row execute function public.module_rules('review', 'status', 'Completed', '1');
create trigger creative_artworks_audit after insert or update or delete on public.creative_artworks
  for each row execute function public.log_record_change('artworks', 'creative', 'task', 'status', 'Completed', '/creative/adhoc/artworks');
create policy creative_artworks_select on public.creative_artworks for select to authenticated using (public.module_level('creative', 'artworks') in ('read', 'write'));
create policy creative_artworks_update on public.creative_artworks for update to authenticated using (public.module_level('creative', 'artworks') = 'write') with check (public.module_level('creative', 'artworks') = 'write');
create policy creative_artworks_delete on public.creative_artworks for delete to authenticated using (public.module_level('creative', 'artworks') = 'write');
create policy creative_artworks_insert on public.creative_artworks for insert to authenticated with check (public.module_level('creative', 'artworks') = 'write' or (public.my_team() = 'marketing' and request_source is not null));
create policy creative_artworks_select_requester on public.creative_artworks for select to authenticated using (requested_by = auth.uid());
alter publication supabase_realtime add table public.creative_artworks;

create table public.brief_overview (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  business_name text,
  location text,
  business_category text,
  website text,
  years_operating numeric,
  description text,
  main_contact text,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.brief_overview(created_at desc);
alter table public.brief_overview enable row level security;
create trigger brief_overview_updated before update on public.brief_overview for each row execute function public.set_updated_at();
create trigger brief_overview_audit after insert or update or delete on public.brief_overview
  for each row execute function public.log_record_change('brief-overview', 'creative', 'business_name', '', 'Completed', '/creative/adhoc/brief-overview');
create policy brief_overview_select on public.brief_overview for select to authenticated using (public.module_level('creative', 'brief-overview') in ('read', 'write'));
create policy brief_overview_update on public.brief_overview for update to authenticated using (public.module_level('creative', 'brief-overview') = 'write') with check (public.module_level('creative', 'brief-overview') = 'write');
create policy brief_overview_delete on public.brief_overview for delete to authenticated using (public.module_level('creative', 'brief-overview') = 'write');
create policy brief_overview_insert on public.brief_overview for insert to authenticated with check (public.module_level('creative', 'brief-overview') = 'write');
alter publication supabase_realtime add table public.brief_overview;

create table public.brief_audience (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  age_group text,
  gender text,
  occupation text,
  income_range text,
  family_profile text,
  local_demographics text,
  booking_behaviour text,
  audience_location text,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.brief_audience(created_at desc);
alter table public.brief_audience enable row level security;
create trigger brief_audience_updated before update on public.brief_audience for each row execute function public.set_updated_at();
create trigger brief_audience_audit after insert or update or delete on public.brief_audience
  for each row execute function public.log_record_change('brief-audience', 'creative', 'age_group', '', 'Completed', '/creative/adhoc/brief-audience');
create policy brief_audience_select on public.brief_audience for select to authenticated using (public.module_level('creative', 'brief-audience') in ('read', 'write'));
create policy brief_audience_update on public.brief_audience for update to authenticated using (public.module_level('creative', 'brief-audience') = 'write') with check (public.module_level('creative', 'brief-audience') = 'write');
create policy brief_audience_delete on public.brief_audience for delete to authenticated using (public.module_level('creative', 'brief-audience') = 'write');
create policy brief_audience_insert on public.brief_audience for insert to authenticated with check (public.module_level('creative', 'brief-audience') = 'write');
alter publication supabase_realtime add table public.brief_audience;

create table public.brief_expectations (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  preferred_content text,
  communication_style text,
  concerns text,
  trust_factors text,
  faqs text,
  preferred_channels text,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.brief_expectations(created_at desc);
alter table public.brief_expectations enable row level security;
create trigger brief_expectations_updated before update on public.brief_expectations for each row execute function public.set_updated_at();
create trigger brief_expectations_audit after insert or update or delete on public.brief_expectations
  for each row execute function public.log_record_change('brief-expectations', 'creative', 'preferred_content', '', 'Completed', '/creative/adhoc/brief-expectations');
create policy brief_expectations_select on public.brief_expectations for select to authenticated using (public.module_level('creative', 'brief-expectations') in ('read', 'write'));
create policy brief_expectations_update on public.brief_expectations for update to authenticated using (public.module_level('creative', 'brief-expectations') = 'write') with check (public.module_level('creative', 'brief-expectations') = 'write');
create policy brief_expectations_delete on public.brief_expectations for delete to authenticated using (public.module_level('creative', 'brief-expectations') = 'write');
create policy brief_expectations_insert on public.brief_expectations for insert to authenticated with check (public.module_level('creative', 'brief-expectations') = 'write');
alter publication supabase_realtime add table public.brief_expectations;

create table public.brief_brand (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  brand_colours text,
  typography text,
  logo_link text,
  logo_rules text,
  tone_of_voice text,
  guidelines_doc text,
  recommended text,
  avoid text,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.brief_brand(created_at desc);
alter table public.brief_brand enable row level security;
create trigger brief_brand_updated before update on public.brief_brand for each row execute function public.set_updated_at();
create trigger brief_brand_audit after insert or update or delete on public.brief_brand
  for each row execute function public.log_record_change('brief-brand', 'creative', 'brand_colours', '', 'Completed', '/creative/adhoc/brief-brand');
create policy brief_brand_select on public.brief_brand for select to authenticated using (public.module_level('creative', 'brief-brand') in ('read', 'write'));
create policy brief_brand_update on public.brief_brand for update to authenticated using (public.module_level('creative', 'brief-brand') = 'write') with check (public.module_level('creative', 'brief-brand') = 'write');
create policy brief_brand_delete on public.brief_brand for delete to authenticated using (public.module_level('creative', 'brief-brand') = 'write');
create policy brief_brand_insert on public.brief_brand for insert to authenticated with check (public.module_level('creative', 'brief-brand') = 'write');
alter publication supabase_realtime add table public.brief_brand;

create table public.brief_services (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  service_name text,
  short_description text,
  target_audience text,
  key_benefits text,
  landing_page text,
  content_notes text,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.brief_services(created_at desc);
alter table public.brief_services enable row level security;
create trigger brief_services_updated before update on public.brief_services for each row execute function public.set_updated_at();
create trigger brief_services_audit after insert or update or delete on public.brief_services
  for each row execute function public.log_record_change('brief-services', 'creative', 'service_name', '', 'Completed', '/creative/adhoc/brief-services');
create policy brief_services_select on public.brief_services for select to authenticated using (public.module_level('creative', 'brief-services') in ('read', 'write'));
create policy brief_services_update on public.brief_services for update to authenticated using (public.module_level('creative', 'brief-services') = 'write') with check (public.module_level('creative', 'brief-services') = 'write');
create policy brief_services_delete on public.brief_services for delete to authenticated using (public.module_level('creative', 'brief-services') = 'write');
create policy brief_services_insert on public.brief_services for insert to authenticated with check (public.module_level('creative', 'brief-services') = 'write');
alter publication supabase_realtime add table public.brief_services;

create table public.brief_design (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  visual_style text,
  layout_guidance text,
  photography_guidance text,
  practitioner_visibility text,
  text_limits text,
  colour_rules text,
  reference_images text,
  design_notes text,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.brief_design(created_at desc);
alter table public.brief_design enable row level security;
create trigger brief_design_updated before update on public.brief_design for each row execute function public.set_updated_at();
create trigger brief_design_audit after insert or update or delete on public.brief_design
  for each row execute function public.log_record_change('brief-design', 'creative', 'visual_style', '', 'Completed', '/creative/adhoc/brief-design');
create policy brief_design_select on public.brief_design for select to authenticated using (public.module_level('creative', 'brief-design') in ('read', 'write'));
create policy brief_design_update on public.brief_design for update to authenticated using (public.module_level('creative', 'brief-design') = 'write') with check (public.module_level('creative', 'brief-design') = 'write');
create policy brief_design_delete on public.brief_design for delete to authenticated using (public.module_level('creative', 'brief-design') = 'write');
create policy brief_design_insert on public.brief_design for insert to authenticated with check (public.module_level('creative', 'brief-design') = 'write');
alter publication supabase_realtime add table public.brief_design;

create table public.brief_content (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  content_formats text,
  calls_to_action text,
  sample_captions text,
  hashtags text,
  keywords text,
  suggested_topics text,
  campaign_notes text,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.brief_content(created_at desc);
alter table public.brief_content enable row level security;
create trigger brief_content_updated before update on public.brief_content for each row execute function public.set_updated_at();
create trigger brief_content_audit after insert or update or delete on public.brief_content
  for each row execute function public.log_record_change('brief-content', 'creative', 'content_formats', '', 'Completed', '/creative/adhoc/brief-content');
create policy brief_content_select on public.brief_content for select to authenticated using (public.module_level('creative', 'brief-content') in ('read', 'write'));
create policy brief_content_update on public.brief_content for update to authenticated using (public.module_level('creative', 'brief-content') = 'write') with check (public.module_level('creative', 'brief-content') = 'write');
create policy brief_content_delete on public.brief_content for delete to authenticated using (public.module_level('creative', 'brief-content') = 'write');
create policy brief_content_insert on public.brief_content for insert to authenticated with check (public.module_level('creative', 'brief-content') = 'write');
alter publication supabase_realtime add table public.brief_content;

create table public.brief_campaign_performance (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  campaign_name text,
  reporting_period text,
  engagement_rate numeric,
  best_posts text,
  reels_performance text,
  carousel_performance text,
  reach numeric,
  impressions numeric,
  recommended_topics text,
  metrics_source text check (metrics_source is null or metrics_source in ('Actual (platform export)', 'Manual estimate', 'Sample data')),
  report_link text,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.brief_campaign_performance(created_at desc);
alter table public.brief_campaign_performance enable row level security;
create trigger brief_campaign_performance_updated before update on public.brief_campaign_performance for each row execute function public.set_updated_at();
create trigger brief_campaign_performance_audit after insert or update or delete on public.brief_campaign_performance
  for each row execute function public.log_record_change('brief-campaign-performance', 'creative', 'campaign_name', '', 'Completed', '/creative/adhoc/brief-campaign-performance');
create policy brief_campaign_performance_select on public.brief_campaign_performance for select to authenticated using (public.module_level('creative', 'brief-campaign-performance') in ('read', 'write'));
create policy brief_campaign_performance_update on public.brief_campaign_performance for update to authenticated using (public.module_level('creative', 'brief-campaign-performance') = 'write') with check (public.module_level('creative', 'brief-campaign-performance') = 'write');
create policy brief_campaign_performance_delete on public.brief_campaign_performance for delete to authenticated using (public.module_level('creative', 'brief-campaign-performance') = 'write');
create policy brief_campaign_performance_insert on public.brief_campaign_performance for insert to authenticated with check (public.module_level('creative', 'brief-campaign-performance') = 'write');
alter publication supabase_realtime add table public.brief_campaign_performance;

create table public.brief_competitors (
  id uuid primary key default gen_random_uuid(),
  client_id uuid references public.clients(id) on delete set null,
  competitor_name text,
  website text,
  social_urls text,
  content_style text,
  strengths text,
  opportunities text,
  reference_links text,
  research_date date,
  remark text,
  custom jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.brief_competitors(created_at desc);
alter table public.brief_competitors enable row level security;
create trigger brief_competitors_updated before update on public.brief_competitors for each row execute function public.set_updated_at();
create trigger brief_competitors_audit after insert or update or delete on public.brief_competitors
  for each row execute function public.log_record_change('brief-competitors', 'creative', 'competitor_name', '', 'Completed', '/creative/adhoc/brief-competitors');
create policy brief_competitors_select on public.brief_competitors for select to authenticated using (public.module_level('creative', 'brief-competitors') in ('read', 'write'));
create policy brief_competitors_update on public.brief_competitors for update to authenticated using (public.module_level('creative', 'brief-competitors') = 'write') with check (public.module_level('creative', 'brief-competitors') = 'write');
create policy brief_competitors_delete on public.brief_competitors for delete to authenticated using (public.module_level('creative', 'brief-competitors') = 'write');
create policy brief_competitors_insert on public.brief_competitors for insert to authenticated with check (public.module_level('creative', 'brief-competitors') = 'write');
alter publication supabase_realtime add table public.brief_competitors;

-- Unified task view (RLS of each underlying table applies: security_invoker).
create view public.all_tasks with (security_invoker = true) as
select 'development' as team, 'backups' as module, id, website::text as title, verification::text as status, next_backup_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.website_backups
union all
select 'development' as team, 'performance' as module, id, website::text as title, null::text as status, null::date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.website_performance
union all
select 'development' as team, 'seo' as module, id, title::text as title, status::text as status, due_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.seo_updates
union all
select 'development' as team, 'blogs' as module, id, blog_title::text as title, blog_status::text as status, due_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.blog_updates
union all
select 'development' as team, 'website-expiry' as module, id, domain::text as title, status::text as status, due_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.website_expiry
union all
select 'development' as team, 'ssl-expiry' as module, id, website::text as title, status::text as status, due_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.ssl_expiry
union all
select 'development' as team, 'daily-check' as module, id, website::text as title, status::text as status, check_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.daily_website_checks
union all
select 'development' as team, 'tools-expiry' as module, id, tool_name::text as title, status::text as status, due_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.dev_tools_expiry
union all
select 'development' as team, 'smtp-expiry' as module, id, smtp_tool::text as title, status::text as status, due_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.smtp_tools_expiry
union all
select 'development' as team, 'google-tracker' as module, id, website::text as title, status::text as status, due_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.google_tracking
union all
select 'development' as team, 'domain-access' as module, id, domain::text as title, status::text as status, due_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.domain_access
union all
select 'marketing' as team, 'spot-calendar' as module, id, content_title::text as title, calendar_status::text as status, content_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.spot_calendar
union all
select 'marketing' as team, 'mailer-reports' as module, id, campaign_name::text as title, null::text as status, send_date::date as due_date, null::uuid as assigned_to, created_at, updated_at from public.mailer_reports
union all
select 'marketing' as team, 'google-ads' as module, id, campaign::text as title, null::text as status, log_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.google_ads_logs
union all
select 'marketing' as team, 'google-analytics' as module, id, website::text as title, null::text as status, report_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.google_analytics
union all
select 'marketing' as team, 'google-setup' as module, id, website::text as title, status::text as status, setup_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.google_client_setup
union all
select 'marketing' as team, 'mailer-scheduler' as module, id, campaign::text as title, campaign_status::text as status, scheduled_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.mailer_scheduler
union all
select 'marketing' as team, 'community-groups' as module, id, group_name::text as title, request_status::text as status, last_checked::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.community_groups
union all
select 'marketing' as team, 'community-tracker' as module, id, post_name::text as title, status::text as status, post_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.community_tracker
union all
select 'marketing' as team, 'blog-youtube' as module, id, content_title::text as title, status::text as status, due_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.blog_youtube_updates
union all
select 'marketing' as team, 'youtube' as module, id, channel_name::text as title, setup_status::text as status, null::date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.youtube_channels
union all
select 'creative' as team, 'web' as module, id, task::text as title, status::text as status, due_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.creative_web_requirements
union all
select 'creative' as team, 'videos' as module, id, task::text as title, status::text as status, due_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.creative_videos
union all
select 'creative' as team, 'artworks' as module, id, task::text as title, status::text as status, due_date::date as due_date, assigned_to as assigned_to, created_at, updated_at from public.creative_artworks;

-- ===== migrations/0003_motivations.sql =====
-- GENERATED: 20 messages for each of All / Development / Marketing / Creative / Admin.
insert into public.daily_motivations (message, team, image) values
  ('Small progress every day creates remarkable results.', 'all', 'admin'),
  ('Great teams are built one honest conversation at a time.', 'all', 'admin'),
  ('Done well beats done fast — and done well, fast beats both.', 'all', 'admin'),
  ('Today is a fresh page. Write something you will be proud of.', 'all', 'admin'),
  ('Consistency turns ordinary effort into extraordinary outcomes.', 'all', 'admin'),
  ('Beyond marketing, beyond healthcare — we deliver beyond expectations.', 'all', 'admin'),
  ('Every task completed is a promise kept to a client.', 'all', 'admin'),
  ('Help someone on your team today. It always comes back.', 'all', 'admin'),
  ('Focus on the next right step, not the whole staircase.', 'all', 'admin'),
  ('Quality is a habit, not an accident.', 'all', 'admin'),
  ('Clarity first, speed second, excellence always.', 'all', 'admin'),
  ('Your work helps healthcare brands reach the people who need them.', 'all', 'admin'),
  ('Celebrate the small wins; they build the big ones.', 'all', 'admin'),
  ('Ask, learn, improve, repeat.', 'all', 'admin'),
  ('A calm mind finishes more than a rushed one.', 'all', 'admin'),
  ('Ownership is the quiet superpower of great teams.', 'all', 'admin'),
  ('Make it clear, make it useful, make it count.', 'all', 'admin'),
  ('The best way to predict tomorrow is to finish today well.', 'all', 'admin'),
  ('Trust the process, respect the deadline.', 'all', 'admin'),
  ('Together we ship what alone we only imagine.', 'all', 'admin'),
  ('Clean code today saves a long night tomorrow.', 'development', 'development'),
  ('Every bug fixed makes the web a little better.', 'development', 'development'),
  ('Consistency in commits is consistency in craft.', 'development', 'development'),
  ('Break the problem down until it becomes obvious.', 'development', 'development'),
  ('A fast, secure website is the best first impression a client can get.', 'development', 'development'),
  ('Read the error message — it is usually trying to help.', 'development', 'development'),
  ('Backups are boring until the day they are everything.', 'development', 'development'),
  ('Learn one new thing about your tools today.', 'development', 'development'),
  ('Ship small, test often, sleep well.', 'development', 'development'),
  ('Great developers make hard things look simple.', 'development', 'development'),
  ('Monitor the quiet sites too; silence is not safety.', 'development', 'development'),
  ('Quality is writing the test before the apology.', 'development', 'development'),
  ('Technology is only as good as the people it serves.', 'development', 'development'),
  ('Curiosity is the best debugging tool you own.', 'development', 'development'),
  ('Performance is a feature your clients feel but never see.', 'development', 'development'),
  ('Document it today and thank yourself next quarter.', 'development', 'development'),
  ('Renew early, worry never.', 'development', 'development'),
  ('Solve the root cause, not the symptom.', 'development', 'development'),
  ('Secure by default, resilient by design.', 'development', 'development'),
  ('Every green check on the daily list is trust earned.', 'development', 'development'),
  ('Growth is the sum of a thousand consistent posts.', 'marketing', 'marketing'),
  ('Know your audience and the message writes itself.', 'marketing', 'marketing'),
  ('Strategy gives the work direction; consistency gives it power.', 'marketing', 'marketing'),
  ('Great communication turns attention into trust.', 'marketing', 'marketing'),
  ('Measure what matters, then improve what you measure.', 'marketing', 'marketing'),
  ('Behind every click is a person with a need.', 'marketing', 'marketing'),
  ('A well-timed email can change someone’s whole day.', 'marketing', 'marketing'),
  ('Creativity attracts. Strategy converts.', 'marketing', 'marketing'),
  ('Be useful before you are promotional.', 'marketing', 'marketing'),
  ('Your campaign is a conversation — listen to the replies.', 'marketing', 'marketing'),
  ('Data tells you what happened; empathy tells you why.', 'marketing', 'marketing'),
  ('Show up every day and the audience will notice.', 'marketing', 'marketing'),
  ('Healthcare marketing is about care first, clicks second.', 'marketing', 'marketing'),
  ('The best headline is the one that respects the reader.', 'marketing', 'marketing'),
  ('Test, learn, scale.', 'marketing', 'marketing'),
  ('Community is built in the comments, not the broadcast.', 'marketing', 'marketing'),
  ('One clear message beats five clever ones.', 'marketing', 'marketing'),
  ('Grow with your audience, not at them.', 'marketing', 'marketing'),
  ('A schedule kept is a brand strengthened.', 'marketing', 'marketing'),
  ('Every campaign is a chance to learn something new about people.', 'marketing', 'marketing'),
  ('Imagination is the first draft of every great design.', 'creative', 'creative'),
  ('Good design is invisible; great design is unforgettable.', 'creative', 'creative'),
  ('Tell the story with pictures and the words will follow.', 'creative', 'creative'),
  ('Originality begins where inspiration meets practice.', 'creative', 'creative'),
  ('Every blank canvas is an invitation.', 'creative', 'creative'),
  ('Simplicity is the ultimate sophistication in design.', 'creative', 'creative'),
  ('Make something today that did not exist yesterday.', 'creative', 'creative'),
  ('Constraints are the secret fuel of creativity.', 'creative', 'creative'),
  ('A frame, a colour, a feeling — that is all a story needs.', 'creative', 'creative'),
  ('Details turn good visuals into trusted brands.', 'creative', 'creative'),
  ('Look at the world like a designer; find beauty in structure.', 'creative', 'creative'),
  ('Iterate bravely; the third version is usually the one.', 'creative', 'creative'),
  ('Your art helps people understand care at a glance.', 'creative', 'creative'),
  ('Visual storytelling turns messages into memories.', 'creative', 'creative'),
  ('Be original, be consistent, be kind to the brief.', 'creative', 'creative'),
  ('Colour carries emotion before a word is read.', 'creative', 'creative'),
  ('Rhythm in motion, clarity in layout.', 'creative', 'creative'),
  ('Great creative work is a team sport.', 'creative', 'creative'),
  ('Trust your eye, then test with the audience.', 'creative', 'creative'),
  ('Create with purpose and the polish takes care of itself.', 'creative', 'creative'),
  ('Leadership is making your team successful and then stepping aside.', 'admin', 'admin'),
  ('Plan the week, protect the priorities, praise the progress.', 'admin', 'admin'),
  ('Clear goals turn busy teams into effective ones.', 'admin', 'admin'),
  ('A team that feels trusted does its best work.', 'admin', 'admin'),
  ('Progress is visible when you look for it. Look today.', 'admin', 'admin'),
  ('Collaboration across teams is where the biggest wins hide.', 'admin', 'admin'),
  ('Remove blockers and the team will move mountains.', 'admin', 'admin'),
  ('Great leaders ask better questions.', 'admin', 'admin'),
  ('Recognise effort publicly, correct privately.', 'admin', 'admin'),
  ('What gets reviewed gets improved.', 'admin', 'admin'),
  ('Delegate outcomes, not tasks.', 'admin', 'admin'),
  ('Alignment is cheaper than rework.', 'admin', 'admin'),
  ('Your steadiness sets the pace for everyone.', 'admin', 'admin'),
  ('Plan for expiry dates the way you plan for growth.', 'admin', 'admin'),
  ('Teamwork turns deadlines into milestones.', 'admin', 'admin'),
  ('Look at the whole board before moving a single piece.', 'admin', 'admin'),
  ('Make time to listen; the answers are already in the room.', 'admin', 'admin'),
  ('Momentum is built from finished work, not busy work.', 'admin', 'admin'),
  ('Culture is what the team does when nobody is watching.', 'admin', 'admin'),
  ('Lead with clarity, decide with data, close with gratitude.', 'admin', 'admin');

-- ===== migrations/0004_clients_tasks.sql =====
-- Shared client profiles, global tasks (with review workflow), comments, task history and app settings.
-- Hand-written. Run after 0001–0003.

-- ───────── clients: one shared record for every team ─────────
alter table public.clients
  add column client_type text not null default 'General Practitioner' check (client_type in ('Specialist', 'General Practitioner')),
  add column joined_on date,
  add column md_name text,
  add column location text,
  add column category text,
  add column website text check (website is null or website ~* '^https?://'),
  add column status text not null default 'active' check (status in ('active', 'inactive', 'archived')),
  add column notes text,
  add column updated_at timestamptz not null default now();
create index on public.clients(status);
create index on public.clients(location);
create trigger clients_updated before update on public.clients for each row execute function public.set_updated_at();

create table public.client_members (
  client_id uuid not null references public.clients(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  primary key (client_id, user_id)
);
create index on public.client_members(user_id);
alter table public.client_members enable row level security;
create policy client_members_read on public.client_members for select to authenticated using (public.my_team() is not null);
create policy client_members_admin on public.client_members for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- clients_read / clients_write (0001) already give every team read access and admins write access.

-- ───────── global tasks ─────────
create table public.tasks (
  id uuid primary key default gen_random_uuid(),
  title text not null check (length(title) between 1 and 300),
  description text,
  client_id uuid references public.clients(id) on delete set null,
  team text not null check (team in ('development', 'marketing', 'creative')),
  assigned_to uuid references public.profiles(id) on delete set null,
  created_by uuid references public.profiles(id) on delete set null,
  reviewer_id uuid references public.profiles(id) on delete set null,
  priority text not null default 'Medium' check (priority in ('Low', 'Medium', 'High', 'Urgent')),
  status text not null default 'New' check (status in ('New', 'Assigned', 'In Progress', 'On Hold', 'Submitted for Review', 'Changes Requested', 'Approved', 'Completed', 'Cancelled')),
  review_status text not null default 'None' check (review_status in ('None', 'Requested', 'Approved', 'Changes Requested')),
  review_rating smallint check (review_rating between 1 and 5),   -- null = not reviewed (never treated as zero)
  date_assigned date default current_date,
  due_date date,
  output_link text check (output_link is null or output_link ~* '^https?://'),
  thumbnail text,
  remarks text,
  completed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index on public.tasks(team, status);
create index on public.tasks(assigned_to);
create index on public.tasks(reviewer_id);
create index on public.tasks(client_id);
create index on public.tasks(due_date);
create index on public.tasks(completed_at);
create trigger tasks_updated before update on public.tasks for each row execute function public.set_updated_at();

create table public.task_comments (
  id uuid primary key default gen_random_uuid(),
  task_id uuid not null references public.tasks(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade default auth.uid(),
  body text not null check (length(body) between 1 and 2000),
  created_at timestamptz not null default now()
);
create index on public.task_comments(task_id, created_at);

create table public.task_events (          -- activity history; written only by triggers
  id uuid primary key default gen_random_uuid(),
  task_id uuid not null references public.tasks(id) on delete cascade,
  user_id uuid references public.profiles(id) on delete set null,
  action text not null,
  detail text not null,
  created_at timestamptz not null default now()
);
create index on public.task_events(task_id, created_at);

-- Workflow guard: the same rules as src/lib/taskflow.ts, enforced in the database.
create or replace function public.tasks_guard() returns trigger
language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid(); adm boolean := public.is_admin();
begin
  if uid is null then return new; end if;     -- service role / migrations
  if tg_op = 'INSERT' then
    new.created_by := uid;
    new.status := case when new.assigned_to is null then 'New' else 'Assigned' end;
    new.review_status := 'None'; new.review_rating := null; new.completed_at := null;
    return new;
  end if;

  if new.review_status is distinct from old.review_status then
    if new.review_status in ('Approved', 'Changes Requested') then
      if not adm and new.reviewer_id is distinct from uid then raise exception 'Only the assigned reviewer (or an admin) can approve or request changes'; end if;
      if not adm and new.assigned_to = uid then raise exception 'You cannot review your own task'; end if;
      if not adm and old.review_status <> 'Requested' then raise exception 'This task has not been submitted for review'; end if;
      new.status := case when new.review_status = 'Approved' then 'Approved' else 'Changes Requested' end;
    elsif new.review_status = 'Requested' then
      if new.reviewer_id is null then raise exception 'Choose a reviewer before requesting a review'; end if;
      new.status := 'Submitted for Review';
    elsif new.review_status = 'None' and not adm then
      raise exception 'Only an admin can reset a review';
    end if;
  elsif new.status is distinct from old.status then
    if new.status = 'Submitted for Review' then
      if new.reviewer_id is null then raise exception 'Choose a reviewer before submitting for review'; end if;
      new.review_status := 'Requested';
    elsif new.status = 'Approved' and new.review_status <> 'Approved' then
      raise exception 'A task can only be Approved by its reviewer';
    elsif new.status = 'Completed' and new.reviewer_id is not null and new.review_status <> 'Approved' then
      raise exception 'This task needs reviewer approval before it can be completed';
    end if;
  end if;

  if new.review_rating is distinct from old.review_rating and new.review_rating is not null
     and not adm and new.reviewer_id is distinct from uid then
    raise exception 'Only the reviewer can record a rating';
  end if;

  if new.status = 'Completed' and old.status <> 'Completed' then new.completed_at := now();
  elsif new.status <> 'Completed' and old.status = 'Completed' then new.completed_at := null;
  else new.completed_at := old.completed_at; end if;
  new.created_by := old.created_by;
  return new;
end $$;
create trigger tasks_guard_trg before insert or update on public.tasks for each row execute function public.tasks_guard();

create or replace function public.tasks_audit() returns trigger
language plpgsql security definer set search_path = public as $$
declare uid uuid := auth.uid(); team_name text := initcap(new.team);
begin
  if tg_op = 'INSERT' then
    insert into public.task_events(task_id, user_id, action, detail) values (new.id, uid, 'created', 'Task created');
    if new.assigned_to is not null and new.assigned_to is distinct from uid then
      insert into public.notifications(user_id, title, body, kind, link) values (new.assigned_to, 'New task assigned', new.title, 'due', '/tasks?open=' || new.id);
    end if;
    return new;
  end if;
  if new.review_status is distinct from old.review_status then
    if new.review_status = 'Requested' then
      insert into public.task_events(task_id, user_id, action, detail) values (new.id, uid, 'review', 'Submitted for review');
      if new.reviewer_id is not null then insert into public.notifications(user_id, title, body, kind, link) values (new.reviewer_id, 'Review requested', new.title, 'due', '/tasks?open=' || new.id); end if;
    elsif new.review_status = 'Approved' then
      insert into public.task_events(task_id, user_id, action, detail) values (new.id, uid, 'approved', 'Task approved by reviewer');
      if new.assigned_to is not null then insert into public.notifications(user_id, title, body, kind, link) values (new.assigned_to, 'Task approved', new.title, 'completed', '/tasks?open=' || new.id); end if;
    elsif new.review_status = 'Changes Requested' then
      insert into public.task_events(task_id, user_id, action, detail) values (new.id, uid, 'changes', 'Reviewer requested changes');
      if new.assigned_to is not null then insert into public.notifications(user_id, title, body, kind, link) values (new.assigned_to, 'Changes requested', new.title, 'due', '/tasks?open=' || new.id); end if;
    end if;
  elsif new.status is distinct from old.status and new.status <> 'Completed' and old.status <> 'Completed' then
    insert into public.task_events(task_id, user_id, action, detail) values (new.id, uid, 'status', 'Status changed to ' || new.status);
  end if;
  if new.status = 'Completed' and old.status <> 'Completed' then
    insert into public.task_events(task_id, user_id, action, detail)
      values (new.id, uid, 'completed', case when new.review_status = 'Approved' then 'Completed (verified by review)' else 'Completed (self-reported, unverified)' end);
    perform public.notify_team('admin', team_name || ' Team completed', team_name || ' Team completed: ' || new.title, 'completed', '/tasks?open=' || new.id);
  elsif new.status <> 'Completed' and old.status = 'Completed' then
    insert into public.task_events(task_id, user_id, action, detail) values (new.id, uid, 'reopened', 'Reopened as ' || new.status);
  end if;
  if new.assigned_to is distinct from old.assigned_to and new.assigned_to is not null then
    insert into public.task_events(task_id, user_id, action, detail) values (new.id, uid, 'assigned', 'Assignee changed');
    if new.assigned_to is distinct from uid then insert into public.notifications(user_id, title, body, kind, link) values (new.assigned_to, 'Task assigned to you', new.title, 'due', '/tasks?open=' || new.id); end if;
  end if;
  return new;
end $$;
create trigger tasks_audit_trg after insert or update on public.tasks for each row execute function public.tasks_audit();

create or replace function public.task_comment_notify() returns trigger
language plpgsql security definer set search_path = public as $$
declare t public.tasks; who text;
begin
  select * into t from public.tasks where id = new.task_id;
  select name into who from public.profiles where id = new.user_id;
  insert into public.notifications(user_id, title, body, kind, link)
    select distinct x, 'New task comment', coalesce(who, 'Someone') || ': ' || left(new.body, 80), 'due', '/tasks?open=' || t.id
    from unnest(array[t.assigned_to, t.reviewer_id, t.created_by]) as x where x is not null and x <> new.user_id;
  return new;
end $$;
create trigger task_comment_notify_trg after insert on public.task_comments for each row execute function public.task_comment_notify();

alter table public.tasks enable row level security;
alter table public.task_comments enable row level security;
alter table public.task_events enable row level security;

create policy tasks_select on public.tasks for select to authenticated
  using (public.can_access_team(team) or assigned_to = auth.uid() or reviewer_id = auth.uid());
create policy tasks_insert on public.tasks for insert to authenticated with check (public.can_access_team(team));
create policy tasks_update on public.tasks for update to authenticated
  using (public.can_access_team(team) or assigned_to = auth.uid() or reviewer_id = auth.uid())
  with check (public.can_access_team(team) or assigned_to = auth.uid() or reviewer_id = auth.uid());
create policy tasks_delete on public.tasks for delete to authenticated using (public.is_admin());

create policy task_comments_select on public.task_comments for select to authenticated using (exists (select 1 from public.tasks t where t.id = task_id));
create policy task_comments_insert on public.task_comments for insert to authenticated
  with check (user_id = auth.uid() and exists (select 1 from public.tasks t where t.id = task_id));
create policy task_events_select on public.task_events for select to authenticated using (exists (select 1 from public.tasks t where t.id = task_id));
-- no insert/update/delete policy on task_events: only the SECURITY DEFINER trigger writes history.

alter publication supabase_realtime add table public.tasks;

-- ───────── app settings (scoring weights, alert schedules, animation toggles…) ─────────
create table public.app_settings (
  key text primary key,
  value jsonb not null,
  updated_by uuid references public.profiles(id) on delete set null,
  updated_at timestamptz not null default now()
);
alter table public.app_settings enable row level security;
create policy app_settings_read on public.app_settings for select to authenticated using (public.my_team() is not null);
create policy app_settings_admin on public.app_settings for all to authenticated using (public.is_admin()) with check (public.is_admin());

-- ===== migrations/0005_customization.sql =====
-- Customization Studio: admin-built registers (custom modules), extra fields on built-in modules, and the checks that keep them safe.
-- Hand-written. Run after 0001–0004.

create table public.custom_modules (
  id uuid primary key default gen_random_uuid(),
  slug text not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{1,38}$'),
  title text not null check (length(title) between 2 and 80),
  team text not null check (team in ('development', 'marketing', 'creative')),
  icon text not null default 'ClipboardList',
  blurb text not null default '',
  fields jsonb not null default '[]'::jsonb,   -- [{key,label,type,options?,required?}]
  archived boolean not null default false,
  created_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint custom_modules_fields_array check (jsonb_typeof(fields) = 'array' and jsonb_array_length(fields) <= 40)
);
create trigger custom_modules_updated before update on public.custom_modules for each row execute function public.set_updated_at();

create table public.custom_records (
  id uuid primary key default gen_random_uuid(),
  module_id uuid not null references public.custom_modules(id) on delete cascade,
  client_id uuid references public.clients(id) on delete set null,
  data jsonb not null default '{}'::jsonb,
  created_by uuid references public.profiles(id) on delete set null,
  updated_by uuid references public.profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint custom_records_data_object check (jsonb_typeof(data) = 'object' and pg_column_size(data) < 30000)
);
create index on public.custom_records(module_id, created_at desc);
create index on public.custom_records(client_id);
create trigger custom_records_updated before update on public.custom_records for each row execute function public.set_updated_at();

create table public.custom_field_definitions (   -- extra fields on built-in modules; values live in each table's "custom" column
  id uuid primary key default gen_random_uuid(),
  module_key text not null,
  key text not null check (key ~ '^[a-z][a-z0-9_]{1,30}$'),
  label text not null check (length(label) between 1 and 60),
  type text not null check (type in ('text', 'longtext', 'number', 'date', 'url', 'select', 'bool', 'file', 'client', 'user')),
  options jsonb not null default '[]'::jsonb,
  required boolean not null default false,
  position int not null default 0,
  archived boolean not null default false,
  created_at timestamptz not null default now(),
  unique (module_key, key)
);

-- Field-level validation for custom records, enforced in the database (the UI cannot bypass it).
create or replace function public.validate_custom_record() returns trigger
language plpgsql security definer set search_path = public as $$
declare spec jsonb; f jsonb; v jsonb; k text; t text; opts jsonb;
begin
  select fields into spec from public.custom_modules where id = new.module_id;
  if spec is null then raise exception 'Unknown custom module'; end if;
  for f in select * from jsonb_array_elements(spec) loop
    k := f->>'key'; t := f->>'type'; v := new.data->k; opts := coalesce(f->'options', '[]'::jsonb);
    if coalesce((f->>'required')::boolean, false) and (v is null or v = 'null'::jsonb or v = '""'::jsonb) and t <> 'bool' then
      raise exception '% is required', f->>'label';
    end if;
    if v is null or v = 'null'::jsonb or v = '""'::jsonb then continue; end if;
    if t = 'number' and jsonb_typeof(v) <> 'number' then raise exception '% must be a number', f->>'label'; end if;
    if t = 'bool' and jsonb_typeof(v) <> 'boolean' then raise exception '% must be yes or no', f->>'label'; end if;
    if t in ('text', 'longtext', 'date', 'url', 'select', 'file') and jsonb_typeof(v) <> 'string' then raise exception '% must be text', f->>'label'; end if;
    if t = 'date' and (v #>> '{}') !~ '^\d{4}-\d{2}-\d{2}$' then raise exception '% must be a date', f->>'label'; end if;
    if t = 'url' and (v #>> '{}') !~* '^https?://' then raise exception '% must start with http:// or https://', f->>'label'; end if;
    if t = 'select' and not (opts @> to_jsonb(v #>> '{}')) then raise exception '% has an invalid option', f->>'label'; end if;
    if t in ('text', 'select', 'url', 'file', 'date') and length(v #>> '{}') > 500 then raise exception '% is too long', f->>'label'; end if;
    if t = 'longtext' and length(v #>> '{}') > 4000 then raise exception '% is too long', f->>'label'; end if;
  end loop;
  return new;
end $$;
create trigger custom_records_validate before insert or update on public.custom_records for each row execute function public.validate_custom_record();

alter table public.custom_modules enable row level security;
alter table public.custom_records enable row level security;
alter table public.custom_field_definitions enable row level security;

create policy custom_modules_read on public.custom_modules for select to authenticated
  using (public.is_admin() or (not archived and public.module_level(team, 'custom:' || id::text) in ('read', 'write')));
create policy custom_modules_admin on public.custom_modules for all to authenticated using (public.is_admin()) with check (public.is_admin());

create policy custom_records_select on public.custom_records for select to authenticated
  using (exists (select 1 from public.custom_modules cm where cm.id = module_id and public.module_level(cm.team, 'custom:' || cm.id::text) in ('read', 'write')));
create policy custom_records_insert on public.custom_records for insert to authenticated
  with check (exists (select 1 from public.custom_modules cm where cm.id = module_id and not cm.archived and public.module_level(cm.team, 'custom:' || cm.id::text) = 'write'));
create policy custom_records_update on public.custom_records for update to authenticated
  using (exists (select 1 from public.custom_modules cm where cm.id = module_id and public.module_level(cm.team, 'custom:' || cm.id::text) = 'write'))
  with check (exists (select 1 from public.custom_modules cm where cm.id = module_id and public.module_level(cm.team, 'custom:' || cm.id::text) = 'write'));
create policy custom_records_delete on public.custom_records for delete to authenticated
  using (exists (select 1 from public.custom_modules cm where cm.id = module_id and public.module_level(cm.team, 'custom:' || cm.id::text) = 'write'));

create policy custom_fields_read on public.custom_field_definitions for select to authenticated using (public.my_team() is not null);
create policy custom_fields_admin on public.custom_field_definitions for all to authenticated using (public.is_admin()) with check (public.is_admin());

create trigger custom_modules_audit after insert or update or delete on public.custom_modules for each row execute function public.log_config_change('custom module');
create trigger custom_fields_audit after insert or update or delete on public.custom_field_definitions for each row execute function public.log_config_change('custom field');
create trigger app_settings_audit after insert or update or delete on public.app_settings for each row execute function public.log_config_change('setting');

alter publication supabase_realtime add table public.custom_records;

-- Per-user notification preferences (in-app is always on; email only when a provider is configured on the server).
create table public.notification_prefs (
  user_id uuid primary key references public.profiles(id) on delete cascade,
  email_enabled boolean not null default false,
  kinds text[] not null default array['expiry', 'due', 'overdue', 'creative', 'completed', 'check', 'priority', 'admin', 'marketing'],
  updated_at timestamptz not null default now()
);
alter table public.notification_prefs enable row level security;
create policy notification_prefs_own on public.notification_prefs for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

-- De-duplication for scheduled reminders: one row per (user, reminder key), so a job can run safely more than once a day.
create table public.reminder_log (
  user_id uuid not null references public.profiles(id) on delete cascade,
  reminder_key text not null,
  sent_on date not null default current_date,
  primary key (user_id, reminder_key, sent_on)
);
alter table public.reminder_log enable row level security;   -- no policies: only the service role (cron job) touches it

-- Private bucket for uploaded files (custom "file" fields). Files are opened through short-lived signed URLs, never public links.
insert into storage.buckets (id, name, public) values ('attachments', 'attachments', false) on conflict do nothing;
create policy attachments_upload on storage.objects for insert to authenticated
  with check (bucket_id = 'attachments' and public.my_team() is not null and (storage.extension(name) = any (array['pdf','png','jpg','jpeg','webp','gif','txt','csv','doc','docx','xls','xlsx'])));
create policy attachments_read on storage.objects for select to authenticated using (bucket_id = 'attachments' and public.my_team() is not null);

-- ===== migrations/0006_scheduled_reminders.sql =====
-- Scheduled reminders: expiry alerts and task due/overdue alerts generated on the server, not in a browser timer.
-- Run after 0001–0005. Triggered daily by /api/cron/reminders (Vercel Cron) or by pg_cron (see README).
-- Safe to run more than once a day: reminder_log (user, key, day) de-duplicates every notification.

create or replace function public.run_reminders() returns integer
language plpgsql security definer set search_path = public as $$
declare
  tz text := coalesce((select value #>> '{}' from public.app_settings where key = 'company_timezone'), 'Asia/Kolkata');
  today date := (now() at time zone tz)::date;
  alert_days int[] := coalesce(
    (select array(select (e)::int from jsonb_array_elements_text(value) e) from public.app_settings where key = 'expiry_alert_days' and jsonb_typeof(value) = 'array'),
    array[90, 60, 30, 14, 7, 1]);
  src record; r record; admin_ids uuid[]; recipients uuid[]; uid uuid;
  d int; k text; sent int := 0; ins int;
begin
  select coalesce(array_agg(id), '{}') into admin_ids from public.profiles where status = 'active' and role = 'admin';

  -- 1. Expiry registers: (table, date column, title column, label, link)
  for src in
    select * from (values
      ('website_expiry', 'expiry_date',    'domain',     'Domain',          '/development/domain-expiry'),
      ('website_expiry', 'hosting_expiry', 'domain',     'Hosting',         '/development/domain-expiry'),
      ('ssl_expiry',     'ssl_expiry_date','website',    'SSL certificate', '/development/ssl-expiry'),
      ('dev_tools_expiry','expiry_date',   'tool_name',  'Development tool','/development/tools-expiry'),
      ('smtp_tools_expiry','expiry_date',  'smtp_tool',  'SMTP tool',       '/development/smtp-expiry'),
      ('domain_access',  'expiry_date',    'domain',     'Domain access',   '/development/domain-access')
    ) as t(tbl, col, title_col, label, link)
  loop
    for r in execute format(
      'select id, %I::text as title, %I::date as due, assigned_to from public.%I where %I is not null and coalesce(status, '''') not in (''Completed'', ''Cancelled'')',
      src.title_col, src.col, src.tbl, src.col)
    loop
      d := r.due - today;
      -- fire on each configured threshold day, and weekly (every 7th day) once expired
      if d = any (alert_days) or (d < 0 and (-d) % 7 = 1) then
        k := format('%s:%s:%s:%s', src.tbl, src.col, r.id, case when d < 0 then 'expired' else d::text end);
        recipients := admin_ids;
        if r.assigned_to is not null and not (r.assigned_to = any (recipients)) then recipients := recipients || r.assigned_to; end if;
        foreach uid in array recipients loop
          insert into public.reminder_log (user_id, reminder_key, sent_on) values (uid, k, today) on conflict do nothing;
          get diagnostics ins = row_count;
          if ins > 0 then
            insert into public.notifications (user_id, title, body, kind, link) values (
              uid,
              case when d < 0 then src.label || ' expired' else src.label || ' expires in ' || d || ' day' || case when d = 1 then '' else 's' end end,
              coalesce(r.title, 'Record') || ' — ' || case when d < 0 then 'expired ' || (-d) || ' day(s) ago (' || r.due || ')' else 'expires on ' || r.due end,
              'expiry', src.link);
            sent := sent + 1;
          end if;
        end loop;
      end if;
    end loop;
  end loop;

  -- 2. Tasks: due today (once) and overdue (once per day) for the assignee; open tasks only
  for r in
    select id, title, due_date, assigned_to, team from public.tasks
    where assigned_to is not null and due_date is not null and due_date <= today
      and status not in ('Completed', 'Cancelled', 'Approved', 'Submitted for Review')
  loop
    d := r.due_date - today;
    k := format('task:%s:%s', r.id, case when d < 0 then 'overdue' else 'due' end);
    insert into public.reminder_log (user_id, reminder_key, sent_on) values (r.assigned_to, k, today) on conflict do nothing;
    get diagnostics ins = row_count;
    if ins > 0 then
      insert into public.notifications (user_id, title, body, kind, link) values (
        r.assigned_to,
        case when d < 0 then 'Task overdue' else 'Task due today' end,
        r.title || case when d < 0 then ' was due ' || r.due_date else ' is due today' end,
        case when d < 0 then 'overdue' else 'due' end, '/tasks');
      sent := sent + 1;
    end if;
  end loop;

  -- housekeeping: the de-duplication log only needs recent days
  delete from public.reminder_log where sent_on < today - 60;
  return sent;
end $$;

-- Only the service role (the cron route) or the database scheduler may run it; never an end user or the anon key.
revoke all on function public.run_reminders() from public, anon, authenticated;
grant execute on function public.run_reminders() to service_role;

-- Optional: if the pg_cron extension is enabled on your Supabase project, schedule it there instead of Vercel Cron:
--   select cron.schedule('ambizcon-reminders', '30 0 * * *', $$select public.run_reminders()$$);   -- 00:30 UTC = 06:00 IST
