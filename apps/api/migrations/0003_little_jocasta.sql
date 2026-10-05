CREATE INDEX `request_auth_event_idx` ON `authorization_request` (`auth_event_id`);--> statement-breakpoint
CREATE INDEX `request_client_idx` ON `authorization_request` (`client_id`);--> statement-breakpoint
CREATE INDEX `connect_transaction_request_idx` ON `connect_transaction` (`request_id`);--> statement-breakpoint
CREATE INDEX `grant_auth_event_idx` ON `grant_ledger` (`auth_event_id`);--> statement-breakpoint
CREATE INDEX `grant_client_idx` ON `grant_ledger` (`client_id`);--> statement-breakpoint
CREATE INDEX `access_token_reference_idx` ON `oauth_access_token` (`reference_id`);--> statement-breakpoint
CREATE INDEX `session_auth_event_idx` ON `session` (`auth_event_id`);