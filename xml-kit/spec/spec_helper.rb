require "bundler/setup"
require "xml/kit"
require "ffaker"
#require "active_support/testing/time_helpers"

Dir[File.join(Dir.pwd, 'spec/support/**/*.rb')].each { |f| require f }
RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
  config.include CertificateHelper
end
