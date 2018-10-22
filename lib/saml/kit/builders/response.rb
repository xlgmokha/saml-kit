# frozen_string_literal: true

module Saml
  module Kit
    module Builders
      # {include:file:lib/saml/kit/builders/templates/response.builder}
      # {include:file:spec/saml/kit/builders/response_spec.rb}
      class Response
        include XmlTemplatable
        attr_reader :user, :request, :issuer, :destination, :now, :configuration
        attr_accessor :id, :version, :status_code, :status_message

        def initialize(
          user, request = nil, configuration: Saml::Kit.configuration
        )
          @user = user
          @request = request
          @id = ::Xml::Kit::Id.generate
          @now = Time.now.utc
          @version = '2.0'
          @status_code = Namespaces::SUCCESS
          @status_message = nil
          @issuer = configuration.entity_id
          @encryption_certificate = request.try(:provider)
            .try(:encryption_certificates).try(:last)
          @encrypt = encryption_certificate.present?
          @configuration = configuration
        end

        def build
          Saml::Kit::Response.new(
            to_xml,
            request_id: request.try(:id),
            configuration: configuration
          )
        end

        def assertion=(value)
          @assertion = value || Null.new
        end

        def assertion
          @assertion ||=
            begin
              assertion = Assertion.new(user, request, configuration: configuration)
              assertion.sign_with(@signing_key_pair) if @signing_key_pair
              assertion.embed_signature = embed_signature unless embed_signature.nil?
              assertion.now = now
              assertion.destination = destination
              assertion.issuer = issuer
              encrypt ? EncryptedAssertion.new(self, assertion) : assertion
            end
        end

        def destination=(value)
          @destination = value
          assertion.destination = value
        end

        def issuer=(value)
          @issuer = value
          assertion.issuer = value
        end

        def now=(value)
          @now = value
          assertion.now = value
        end

        def embed_signature=(value)
          @embed_signature = value
          assertion.embed_signature = value
        end

        private

        def response_options
          options = {
            ID: id,
            Version: version,
            IssueInstant: now.iso8601,
            Consent: Namespaces::UNSPECIFIED,
            xmlns: Namespaces::PROTOCOL,
          }
          options[:Destination] = destination if destination.present?
          options[:InResponseTo] = request.try(:id) if request.present?
          options
        end
      end
    end
  end
end
