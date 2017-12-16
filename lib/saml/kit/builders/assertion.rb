module Saml
  module Kit
    module Builders
      class Assertion
        include Templatable
        extend Forwardable

        def_delegators :@response_builder, :encrypt, :embed_signature, :request, :issuer, :reference_id, :now, :configuration, :user, :version, :destination, :encryption_certificate

        def initialize(response_builder)
          @response_builder = response_builder
        end

        def name_id_format
          request.name_id_format
        end

        def name_id
          user.name_id_for(name_id_format)
        end

        def assertion_attributes
          user.assertion_attributes_for(request)
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
          {
            InResponseTo: request.id,
            NotOnOrAfter: 3.hours.since(now).utc.iso8601,
            Recipient: destination,
          }
        end

        def conditions_options
          {
            NotBefore: now.utc.iso8601,
            NotOnOrAfter: configuration.session_timeout.from_now.utc.iso8601,
          }
        end

        def authn_statement_options
          {
            AuthnInstant: now.iso8601,
            SessionIndex: reference_id,
            SessionNotOnOrAfter: 3.hours.since(now).utc.iso8601,
          }
        end
      end
    end
  end
end
