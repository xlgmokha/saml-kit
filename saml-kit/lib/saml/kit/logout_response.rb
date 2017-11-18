module Saml
  module Kit
    class LogoutResponse < Document
      def initialize(xml)
        super(xml, name: "LogoutResponse", query_string_parameter: 'SAMLResponse')
      end

      def issue_instant
        to_h[name]['IssueInstant']
      end

      def status_code
        to_h[name]['Status']['StatusCode']['Value']
      end

      def in_response_to
        to_h[name]['InResponseTo']
      end

      def destination
        to_h[name]['Destination']
      end

      def provider
        registry.metadata_for(issuer)
      end

      private

      class Builder
        attr_accessor :id, :issuer, :version, :status_code, :sign, :now, :destination
        attr_reader :request

        def initialize(user, request, configuration: Saml::Kit.configuration, sign: true)
          @user = user
          @now = Time.now.utc
          @request = request
          @id = SecureRandom.uuid
          @version = "2.0"
          @status_code = Namespaces::SUCCESS
          @sign = sign
          @issuer = configuration.issuer
        end

        def to_xml
          Signature.sign(id, sign: sign) do |xml, signature|
            xml.LogoutResponse logout_response_options do
              xml.Issuer(issuer, xmlns: Namespaces::ASSERTION)
              signature.template(xml)
              xml.Status do
                xml.StatusCode Value: status_code
              end
            end
          end
        end

        def build
          LogoutResponse.new(to_xml)
        end

        private

        def logout_response_options
          {
            xmlns: Namespaces::PROTOCOL,
            ID: "_#{id}",
            Version: "2.0",
            IssueInstant: now.utc.iso8601,
            Destination: destination,
            InResponseTo: request.id,
          }
        end
      end
    end
  end
end
