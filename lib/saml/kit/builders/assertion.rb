module Saml
  module Kit
    module Builders
      class Assertion
        include Templatable
        attr_reader :configuration

        def initialize(response_builder)
          @response_builder = response_builder
          @configuration = response_builder.configuration
        end

        def encrypt
          @response_builder.encrypt
        end

        def sign
          @response_builder.sign
        end

        def request
          @response_builder.request
        end

        def issuer
          @response_builder.issuer
        end

        def name_id_format
          request.name_id_format
        end

        def name_id
          @response_builder.user.name_id_for(name_id_format)
        end

        def assertion_attributes
          @response_builder.user.assertion_attributes_for(request)
        end

        def reference_id
          @response_builder.reference_id
        end

        private

        def assertion_options
          {
            ID: reference_id,
            IssueInstant: @response_builder.now.iso8601,
            Version: "2.0",
            xmlns: Namespaces::ASSERTION,
          }
        end

        def subject_confirmation_data_options
          {
            InResponseTo: request.id,
            NotOnOrAfter: 3.hours.since(@response_builder.now).utc.iso8601,
            Recipient: request.assertion_consumer_service_url,
          }
        end

        def conditions_options
          {
            NotBefore: @response_builder.now.utc.iso8601,
            NotOnOrAfter: configuration.session_timeout.from_now.utc.iso8601,
          }
        end

        def authn_statement_options
          {
            AuthnInstant: @response_builder.now.iso8601,
            SessionIndex: reference_id,
            SessionNotOnOrAfter: 3.hours.since(@response_builder.now).utc.iso8601,
          }
        end
      end
    end
  end
end
