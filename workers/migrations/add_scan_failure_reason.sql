ALTER TABLE scan_results
ADD COLUMN IF NOT EXISTS failure_reason text;
