# frozen_string_literal: true

module Saml
  module Kit
    module Builders
      # {include:file:lib/saml/kit/builders/templates/response.builder}
      # {include:file:spec/saml/builders/response_spec.rb}
      class Response
        include XmlTemplatable
        attr_reader :user, :request
        attr_accessor :id, :reference_id, :now
        attr_accessor :version, :status_code
        attr_accessor :issuer, :destination
        attr_reader :configuration

        def initialize(user, request = nil, configuration: Saml::Kit.configuration)
          @user = user
          @request = request
          @id = ::Xml::Kit::Id.generate
          @reference_id = ::Xml::Kit::Id.generate
          @now = Time.now.utc
          @version = '2.0'
          @status_code = Namespaces::SUCCESS
          @issuer = configuration.entity_id
          @encryption_certificate = request.try(:provider).try(:encryption_certificates).try(:last)
          @encrypt = encryption_certificate.present?
          @configuration = configuration
        end

        def build
          Saml::Kit::Response.new(to_xml, request_id: request.try(:id), configuration: configuration)
        end

        def assertion
          @assertion ||=
            begin
              assertion = Saml::Kit::Builders::Assertion.new(self, embed_signature)
              if encrypt
                Saml::Kit::Builders::EncryptedAssertion.new(self, assertion)
              else
                assertion
              end
            end
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
          options[:InResponseTo] = request.id if request.present?
          options
        end
      end
    end
  end
end
