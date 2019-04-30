# frozen_string_literal: true

module Saml
  module Kit
    module Builders
      # {include:file:lib/saml/kit/builders/templates/authentication_request.builder}
      # {include:file:spec/saml/kit/builders/authentication_request_spec.rb}
      class AuthenticationRequest
        include XmlTemplatable
        attr_accessor :id, :now, :issuer, :assertion_consumer_service_url
        attr_accessor :name_id_format, :destination
        attr_accessor :version
        attr_accessor :force_authn
        attr_reader :configuration

        def initialize(configuration: Saml::Kit.configuration)
          @configuration = configuration
          @id = ::Xml::Kit::Id.generate
          @issuer = configuration.entity_id
          @name_id_format = Namespaces::PERSISTENT
          @now = Time.now.utc
          @version = '2.0'
        end

        def build
          Saml::Kit::AuthenticationRequest.new(to_xml)
        end

        private

        def request_options
          options = {
            'xmlns:samlp' => Namespaces::PROTOCOL,
            'xmlns:saml' => Namespaces::ASSERTION,
            ID: id,
            Version: version,
            IssueInstant: now.utc.iso8601,
            Destination: destination,
          }
          options[:ForceAuthn] = force_authn if !force_authn.nil?
          if assertion_consumer_service_url.present?
            options[:AssertionConsumerServiceURL] =
              assertion_consumer_service_url
          end
          options
        end
      end
    end
  end
end
