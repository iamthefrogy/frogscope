-- v2.1: schedules fire in a chosen IANA timezone, not always UTC.
--
-- `time_of_day` was always stored and matched against UTC — a browser
-- entering "09:35" meaning its own local time got a schedule that actually
-- fired at 09:35 UTC, which in most timezones is a different wall-clock
-- moment. `next_run_at` (scan/scheduler.py) is still always computed and
-- stored in UTC, same as before; only the interpretation of `time_of_day`
-- changes, from "UTC" to "this column".

ALTER TABLE schedules ADD COLUMN timezone TEXT NOT NULL DEFAULT 'UTC';
