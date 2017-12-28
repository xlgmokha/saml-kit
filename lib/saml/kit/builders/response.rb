module Saml
  module Kit
    module Builders
      # {include:file:spec/saml/builders/response_spec.rb}
      class Response
        include XmlTemplatable
        attr_reader :user, :request
        attr_accessor :id, :reference_id, :now
        attr_accessor :version, :status_code
        attr_accessor :issuer, :destination, :encrypt
        attr_reader :configuration

        def initialize(user, request, configuration: Saml::Kit.configuration)
          @user = user
          @request = request
          @id = ::Xml::Kit::Id.generate
          @reference_id = ::Xml::Kit::Id.generate
          @now = Time.now.utc
          @version = "2.0"
          @status_code = Namespaces::SUCCESS
          @issuer = configuration.issuer
          @encrypt = encryption_certificate.present?
          @configuration = configuration
        end

        def build
          Saml::Kit::Response.new(to_xml, request_id: request.id, configuration: configuration)
        end

        def encryption_certificate
          request.provider.encryption_certificates.first
        rescue => error
          Saml::Kit.logger.error(error)
          nil
        end

        private

        def assertion
          @assertion ||= Saml::Kit::Builders::Assertion.new(self)
          if encrypt
            Saml::Kit::Builders::EncryptedAssertion.new(self, @assertion)
          else
            @assertion
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
      end
    end
  end
end
