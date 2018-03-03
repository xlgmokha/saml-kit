# frozen_string_literal: true

module Saml
  module Kit
    module Builders
      # {include:file:lib/saml/kit/builders/templates/assertion.builder}
      class Assertion
        include XmlTemplatable
        extend Forwardable

        def_delegators :@response_builder, :request, :issuer, :reference_id, :now, :configuration, :user, :version, :destination

        def initialize(response_builder, embed_signature)
          @response_builder = response_builder
          self.embed_signature = embed_signature
        end

        def name_id_format
          request.try(:name_id_format) || Saml::Kit::Namespaces::PERSISTENT
        end

        def name_id
          user.name_id_for(name_id_format)
        end

        def assertion_attributes
          user.assertion_attributes_for(request)
        end

        def signing_key_pair
          super || @response_builder.signing_key_pair
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
          options = { NotOnOrAfter: 3.hours.since(now).utc.iso8601 }
          options[:Recipient] = destination if destination.present?
          options[:InResponseTo] = request.id if request.present?
          options
        end

        def conditions_options
          {
            NotBefore: now.utc.iso8601,
            NotOnOrAfter: configuration.session_timeout.since(now).utc.iso8601,
          }
        end

        def authn_statement_options
          {
            AuthnInstant: now.iso8601,
            SessionIndex: reference_id,
            SessionNotOnOrAfter: configuration.session_timeout.since(now).utc.iso8601,
          }
        end
      end
    end
  end
end
