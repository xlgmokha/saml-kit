# frozen_string_literal: true

module Saml
  module Kit
    module Builders
      # This class is responsible for building a SAML Assertion
      # {include:file:lib/saml/kit/builders/templates/assertion.builder}
      class Assertion
        include XmlTemplatable

        attr_reader :user, :request, :configuration
        attr_accessor :reference_id
        attr_accessor :now, :destination
        attr_accessor :issuer, :version
        attr_accessor :default_name_id_format

        def initialize(user, request = nil, embed_signature, configuration: Saml::Kit.configuration, now: Time.now.utc, destination: nil, signing_key_pair: nil, issuer: nil)
          @user = user
          @request = request
          @destination = destination
          @configuration = configuration
          @issuer = issuer || configuration.entity_id
          @reference_id = ::Xml::Kit::Id.generate
          @version = '2.0'
          @now = now
          @signing_key_pair = signing_key_pair
          self.embed_signature = embed_signature
          self.default_name_id_format = Saml::Kit::Namespaces::UNSPECIFIED_NAMEID
        end

        def name_id_format
          request.try(:name_id_format)
        end

        def name_id
          user.name_id_for(name_id_format)
        end

        def assertion_attributes
          return {} unless user.respond_to?(:assertion_attributes_for)
          user.assertion_attributes_for(request)
        end

        def build
          Saml::Kit::Assertion.new(to_xml, configuration: configuration)
        end

        private

        def assertion_options
          {
            ID: reference_id,
            IssueInstant: now.iso8601,
            Version: version,
            xmlns: Namespaces::ASSERTION,
          }
        end

        def subject_confirmation_data_options
          options = {}
          options[:InResponseTo] = request.id if request.present?
          options[:Recipient] = destination if destination.present?
          options[:NotOnOrAfter] = (now + 5.minutes).utc.iso8601
          options
        end

        def conditions_options
          {
            NotBefore: now.utc.iso8601,
            NotOnOrAfter: not_on_or_after.iso8601,
          }
        end

        def authn_statement_options
          {
            AuthnInstant: now.iso8601,
            SessionIndex: reference_id,
          }
        end

        def name_id_options
          { Format: name_id_format || default_name_id_format }
        end

        def not_on_or_after
          configuration.session_timeout.since(now).utc
        end
      end
    end
  end
end
