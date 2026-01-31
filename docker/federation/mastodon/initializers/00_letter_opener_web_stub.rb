# frozen_string_literal: true

# The official Mastodon docker image installs production-only gems.
# Some initializers reference LetterOpenerWeb, which isn't present.
#
# This stub keeps Mastodon bootable for federation smoke tests.
module LetterOpenerWeb
  class Engine
    def self.call(_env)
      [404, {"content-type" => "text/plain"}, ["Not Found"]]
    end
  end

  class LettersController
    def self.content_security_policy(&_block)
    end

    def self.after_action(&_block)
    end
  end
end

