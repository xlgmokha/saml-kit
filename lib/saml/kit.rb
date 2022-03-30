# frozen_string_literal: true

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
require 'net/hippie'
require 'nokogiri'
require 'securerandom'
require 'uri'
require 'xml/kit'

require 'saml/kit/concerns/buildable'
require 'saml/kit/concerns/requestable'
require 'saml/kit/concerns/respondable'
require 'saml/kit/concerns/serializable'
require 'saml/kit/concerns/translatable'
require 'saml/kit/concerns/trustable'
require 'saml/kit/concerns/validatable'
require 'saml/kit/concerns/xml_parseable'
require 'saml/kit/concerns/xml_templatable'
require 'saml/kit/concerns/xsd_validatable'

require 'saml/kit/builders'
require 'saml/kit/namespaces'
require 'saml/kit/document'

require 'saml/kit/assertion'
require 'saml/kit/attribute_statement'
require 'saml/kit/authentication_request'
require 'saml/kit/bindings'
require 'saml/kit/conditions'
require 'saml/kit/configuration'
require 'saml/kit/default_registry'
require 'saml/kit/logout_response'
require 'saml/kit/logout_request'
require 'saml/kit/metadata'
require 'saml/kit/deprecated/metadata'
require 'saml/kit/null_assertion'
require 'saml/kit/organization'
require 'saml/kit/parser'
require 'saml/kit/composite_metadata'
require 'saml/kit/response'
require 'saml/kit/identity_provider_metadata'
require 'saml/kit/invalid_document'
require 'saml/kit/service_provider_metadata'
require 'saml/kit/signature'

I18n.load_path +=
  Dir[File.expand_path('kit/locales/*.yml', File.dirname(__FILE__))]

module Saml
  # This module is the container for all classes/modules in this gem.
  module Kit
    # This class provides a global access to the
    # default SAML configuration. This is useful
    # for long running processes.
    class << self
      def configuration
        @configuration ||= Saml::Kit::Configuration.new
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
