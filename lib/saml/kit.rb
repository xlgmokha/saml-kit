require 'saml/kit/version'

require 'active_model'
require 'active_support/core_ext/date/calculations'
require 'active_support/core_ext/hash/conversions'
require 'active_support/core_ext/hash/indifferent_access'
require 'active_support/core_ext/numeric/time'
require 'active_support/deprecation'
require 'active_support/duration'
require 'forwardable'
require 'logger'
require 'net/http'
require 'nokogiri'
require 'securerandom'
require 'uri'
require 'xml/kit'

require 'saml/kit/buildable'
require 'saml/kit/builders'
require 'saml/kit/namespaces'
require 'saml/kit/serializable'
require 'saml/kit/xsd_validatable'
require 'saml/kit/respondable'
require 'saml/kit/requestable'
require 'saml/kit/trustable'
require 'saml/kit/translatable'
require 'saml/kit/document'

require 'saml/kit/assertion'
require 'saml/kit/authentication_request'
require 'saml/kit/bindings'
require 'saml/kit/configuration'
require 'saml/kit/default_registry'
require 'saml/kit/logout_response'
require 'saml/kit/logout_request'
require 'saml/kit/metadata'
require 'saml/kit/null_assertion'
require 'saml/kit/composite_metadata'
require 'saml/kit/response'
require 'saml/kit/identity_provider_metadata'
require 'saml/kit/invalid_document'
require 'saml/kit/service_provider_metadata'
require 'saml/kit/signature'

I18n.load_path +=
  Dir[File.expand_path('kit/locales/*.yml', File.dirname(__FILE__))]

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

      def registry
        configuration.registry
      end

      def deprecate(message)
        @deprecation ||= ActiveSupport::Deprecation.new('2.0.0', 'saml-kit')
        @deprecation.deprecation_warning(message)
      end
    end
  end
end
