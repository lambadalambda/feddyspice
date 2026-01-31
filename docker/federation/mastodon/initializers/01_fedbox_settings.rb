# frozen_string_literal: true

# The official Mastodon docker image runs as a non-root user, and `/opt/mastodon/db`
# is not writable in the image. Rails defaults to dumping `db/schema.rb` after
# migrations, but for federation-in-a-box smoke tests we don't need schema dumps.
Rails.application.config.active_record.dump_schema_after_migration = false

if defined?(ActiveRecord)
  ActiveRecord.dump_schema_after_migration = false
end

