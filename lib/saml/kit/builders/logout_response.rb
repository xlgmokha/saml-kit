module Saml
  module Kit
    module Builders
      class LogoutResponse
        include Saml::Kit::Templatable
        attr_accessor :id, :issuer, :version, :status_code, :now, :destination
        attr_reader :request
        attr_reader :configuration

        def initialize(request, configuration: Saml::Kit.configuration)
          @configuration = configuration
          @id = Id.generate
          @issuer = configuration.issuer
          @now = Time.now.utc
          @request = request
          @status_code = Namespaces::SUCCESS
          @version = "2.0"
        end

        def build
          Saml::Kit::LogoutResponse.new(to_xml, request_id: request.id)
        end

        private

        def logout_response_options
          {
            xmlns: Namespaces::PROTOCOL,
            ID: id,
            Version: version,
            IssueInstant: now.utc.iso8601,
            Destination: destination,
            InResponseTo: request.id,
          }
        end
      end
    end
  end
end
