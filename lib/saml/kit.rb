require "saml/kit/version"

require "active_model"
require "active_support/core_ext/date/calculations"
require "active_support/core_ext/hash/conversions"
require "active_support/core_ext/hash/indifferent_access"
require "active_support/core_ext/numeric/time"
require "active_support/deprecation"
require "active_support/duration"
require "builder"
require "logger"
require "net/http"
require "nokogiri"
require "securerandom"
require "xmldsig"

require "saml/kit/buildable"
require "saml/kit/builders"
require "saml/kit/namespaces"
require "saml/kit/serializable"
require "saml/kit/xsd_validatable"
require "saml/kit/respondable"
require "saml/kit/requestable"
require "saml/kit/trustable"
require "saml/kit/document"

require "saml/kit/authentication_request"
require "saml/kit/bindings"
require "saml/kit/certificate"
require "saml/kit/configuration"
require "saml/kit/crypto"
require "saml/kit/cryptography"
require "saml/kit/default_registry"
require "saml/kit/fingerprint"
require "saml/kit/logout_response"
require "saml/kit/logout_request"
require "saml/kit/metadata"
require "saml/kit/response"
require "saml/kit/identity_provider_metadata"
require "saml/kit/invalid_document"
require "saml/kit/self_signed_certificate"
require "saml/kit/service_provider_metadata"
require "saml/kit/signature"
require "saml/kit/xml"

I18n.load_path += Dir[File.expand_path("kit/locales/*.yml", File.dirname(__FILE__))]

module Saml
  module Kit
    class << self
      def configuration
        @config ||= Saml::Kit::Configuration.new
      end

      def configure
        yield configuration
      end

      def logger
        configuration.logger
      end
    end
  end
end
