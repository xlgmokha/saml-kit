require "saml/kit/version"

require "builder"
require "securerandom"
require "active_support/duration"
require "active_support/core_ext/numeric/time"
require "active_support/core_ext/hash/conversions"
require "saml/kit/authentication_request"
require "saml/kit/configuration"
require "saml/kit/namespaces"
require "saml/kit/request"
require "saml/kit/response"
require "saml/kit/service_provider_registry"
require "saml/kit/identity_provider_metadata"
require "saml/kit/service_provider_metadata"

module Saml
  module Kit
    def self.configuration
      @config ||= Saml::Kit::Configuration.new
    end

    def self.configure
      yield configuration
    end
  end
end
