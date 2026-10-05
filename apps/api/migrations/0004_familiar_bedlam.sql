CREATE TABLE `credential_clock` (
	`id` integer PRIMARY KEY NOT NULL,
	`revision` integer DEFAULT 0 NOT NULL,
	CONSTRAINT "credential_clock_singleton" CHECK("credential_clock"."id" = 1)
);
--> statement-breakpoint
ALTER TABLE `audit` ADD `subject_user_id` text;--> statement-breakpoint
ALTER TABLE `audit` ADD `subject_linuxdo_id` integer;--> statement-breakpoint
ALTER TABLE `audit` ADD `subject_username` text;--> statement-breakpoint
ALTER TABLE `audit` ADD `upstream_client_id` text;--> statement-breakpoint
ALTER TABLE `audit` ADD `connect_transaction_id` text;--> statement-breakpoint
ALTER TABLE `audit` ADD `identity_confirmed` integer DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE `audit` ADD `verification_purpose` text;--> statement-breakpoint
CREATE INDEX `audit_subject_time_idx` ON `audit` (`subject_user_id`,`created_at`,`id`);--> statement-breakpoint
CREATE INDEX `audit_upstream_time_idx` ON `audit` (`upstream_client_id`,`created_at`,`id`);--> statement-breakpoint
ALTER TABLE `connect_transaction` ADD `started_credential_revision` integer;--> statement-breakpoint
ALTER TABLE `user` ADD `credential_revision` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `user` ADD `last_authenticated_at` integer;--> statement-breakpoint
ALTER TABLE `user` ADD `last_login_method` text;--> statement-breakpoint
ALTER TABLE `user` ADD `last_trust_level` integer;--> statement-breakpoint
INSERT INTO credential_clock (id, revision) VALUES (1, 0);--> statement-breakpoint
CREATE TRIGGER user_credential_revision AFTER UPDATE OF credential_epoch ON user
WHEN NEW.credential_epoch != OLD.credential_epoch
BEGIN
  UPDATE credential_clock SET revision = revision + 1 WHERE id = 1;
  UPDATE user SET credential_revision = (SELECT revision FROM credential_clock WHERE id = 1) WHERE id = NEW.id;
END;--> statement-breakpoint
UPDATE user SET
  last_authenticated_at = (SELECT created_at FROM auth_event WHERE user_id = user.id ORDER BY created_at DESC, id DESC LIMIT 1),
  last_login_method = (SELECT login_method FROM auth_event WHERE user_id = user.id ORDER BY created_at DESC, id DESC LIMIT 1),
  last_trust_level = (SELECT trust_level FROM auth_event WHERE user_id = user.id ORDER BY created_at DESC, id DESC LIMIT 1);--> statement-breakpoint
UPDATE audit SET result = 'failed' WHERE action = 'account.login_failed' AND event_key IS NULL;
