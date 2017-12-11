module Saml
  module Kit
    module Builders
      class Response
        include Templatable
        attr_reader :user, :request
        attr_accessor :id, :reference_id, :now
        attr_accessor :version, :status_code
        attr_accessor :issuer, :sign, :destination, :encrypt
        attr_reader :configuration

        def initialize(user, request, configuration: Saml::Kit.configuration)
          @user = user
          @request = request
          @id = Id.generate
          @reference_id = Id.generate
          @now = Time.now.utc
          @version = "2.0"
          @status_code = Namespaces::SUCCESS
          @issuer = configuration.issuer
          @destination = destination_for(request)
          @sign = want_assertions_signed
          @encrypt = false
          @configuration = configuration
        end

        def want_assertions_signed
          request.provider.want_assertions_signed
        rescue => error
          Saml::Kit.logger.error(error)
          true
        end

        def build
          Saml::Kit::Response.new(to_xml, request_id: request.id)
        end

        private

        def encryption_certificate
          request.provider.encryption_certificates.first
        end

        def destination_for(request)
          if request.signed? && request.trusted?
            request.assertion_consumer_service_url || request.provider.assertion_consumer_service_for(binding: :http_post).try(:location)
          else
            request.provider.assertion_consumer_service_for(binding: :http_post).try(:location)
          end
        end

        def response_options
          {
            ID: id,
            Version: version,
            IssueInstant: now.iso8601,
            Destination: destination,
            Consent: Namespaces::UNSPECIFIED,
            InResponseTo: request.id,
            xmlns: Namespaces::PROTOCOL,
          }
        end

        def assertion_options
          {
            ID: reference_id,
            IssueInstant: now.iso8601,
            Version: "2.0",
            xmlns: Namespaces::ASSERTION,
          }
        end

        def subject_confirmation_data_options
          {
            InResponseTo: request.id,
            NotOnOrAfter: 3.hours.since(now).utc.iso8601,
            Recipient: request.assertion_consumer_service_url,
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
            SessionIndex: assertion_options[:ID],
            SessionNotOnOrAfter: 3.hours.since(now).utc.iso8601,
          }
        end
      end
    end
  end
end
