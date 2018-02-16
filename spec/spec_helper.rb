require 'simplecov'
SimpleCov.start do
  add_filter '/spec/'
end
require 'bundler/setup'
require 'saml/kit'
require 'saml/kit/rspec'
require 'active_support/testing/time_helpers'
require 'ffaker'
require 'webmock/rspec'

Saml::Kit.configuration.logger.level = Xml::Kit.logger.level = Logger::FATAL

Dir[File.join(Dir.pwd, 'spec/support/**/*.rb')].each { |f| require f }
RSpec.configure do |config|
  config.include ActiveSupport::Testing::TimeHelpers
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = '.rspec_status'

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
  config.after do
    travel_back
  end
end
