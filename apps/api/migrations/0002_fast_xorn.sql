-- Additive migration: no table replacement, foreign-key toggle, or secret rotation.
ALTER TABLE `app_settings` ADD `min_trust_level` integer DEFAULT 0 NOT NULL CONSTRAINT `app_min_trust_level_range` CHECK (`min_trust_level` BETWEEN 0 AND 4);--> statement-breakpoint
ALTER TABLE `audit` ADD `actor_type` text DEFAULT 'unknown' NOT NULL;--> statement-breakpoint
ALTER TABLE `audit` ADD `actor_linuxdo_id` integer;--> statement-breakpoint
ALTER TABLE `audit` ADD `actor_username` text;--> statement-breakpoint
ALTER TABLE `audit` ADD `actor_name` text;--> statement-breakpoint
ALTER TABLE `audit` ADD `target_type` text;--> statement-breakpoint
ALTER TABLE `audit` ADD `target_name` text;--> statement-breakpoint
ALTER TABLE `audit` ADD `client_id` text;--> statement-breakpoint
ALTER TABLE `audit` ADD `app_name` text;--> statement-breakpoint
ALTER TABLE `audit` ADD `login_method` text;--> statement-breakpoint
ALTER TABLE `audit` ADD `trust_level` integer;--> statement-breakpoint
ALTER TABLE `audit` ADD `result` text DEFAULT 'success' NOT NULL;--> statement-breakpoint
ALTER TABLE `audit` ADD `reason` text;--> statement-breakpoint
ALTER TABLE `audit` ADD `request_id` text;--> statement-breakpoint
ALTER TABLE `audit` ADD `changes` text;--> statement-breakpoint
ALTER TABLE `audit` ADD `event_key` text;--> statement-breakpoint
CREATE UNIQUE INDEX `audit_event_key_unique` ON `audit` (`event_key`);--> statement-breakpoint
CREATE INDEX `audit_time_idx` ON `audit` (`created_at`,`id`);--> statement-breakpoint
CREATE INDEX `audit_client_time_idx` ON `audit` (`client_id`,`created_at`,`id`);--> statement-breakpoint
CREATE INDEX `audit_actor_time_idx` ON `audit` (`actor_id`,`created_at`,`id`);--> statement-breakpoint
ALTER TABLE `auth_event` ADD `trust_level` integer;--> statement-breakpoint
ALTER TABLE `grant_ledger` ADD `request_id` text;--> statement-breakpoint
ALTER TABLE `oauth_client` ADD `secret_ciphertext` text;--> statement-breakpoint
UPDATE auth_event SET trust_level = json_extract(profile, '$.trust_level')
WHERE json_valid(profile) AND json_type(profile, '$.trust_level') = 'integer'
AND json_extract(profile, '$.trust_level') BETWEEN 0 AND 4;--> statement-breakpoint
UPDATE audit SET actor_type = 'user' WHERE actor_id IS NOT NULL;--> statement-breakpoint
UPDATE audit SET result = 'pending' WHERE action = 'authorization.code_created';--> statement-breakpoint
UPDATE audit SET client_id = target_id, target_type = 'app'
WHERE action LIKE 'authorization.%' AND EXISTS (SELECT 1 FROM oauth_client WHERE client_id = audit.target_id);--> statement-breakpoint
UPDATE audit SET client_id = (SELECT client_id FROM oauth_client WHERE id = audit.target_id), target_type = 'app'
WHERE action LIKE 'app.%';
