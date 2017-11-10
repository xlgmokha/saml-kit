require "saml/kit/version"

require "active_model"
require "active_support/core_ext/date/calculations"
require "active_support/core_ext/hash/conversions"
require "active_support/core_ext/numeric/time"
require "active_support/duration"
require "builder"
require "net/http"
require "nokogiri"
require "securerandom"
require "xmldsig"

require "saml/kit/xsd_validatable"
require "saml/kit/authentication_request"
require "saml/kit/configuration"
require "saml/kit/content"
require "saml/kit/default_registry"
require "saml/kit/fingerprint"
require "saml/kit/namespaces"
require "saml/kit/metadata"
require "saml/kit/request"
require "saml/kit/response"
require "saml/kit/identity_provider_metadata"
require "saml/kit/invalid_request"
require "saml/kit/self_signed_certificate"
require "saml/kit/service_provider_metadata"
require "saml/kit/signature"
require "saml/kit/xml"

I18n.load_path += Dir[File.expand_path("kit/locales/*.yml", File.dirname(__FILE__))]

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
