module Saml
  module Kit
    class LogoutResponse < Document
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
          provider = configuration.registry.metadata_for(@issuer)
          if provider
            @destination = provider.single_logout_service_for(binding: :http_post).try(:location)
          end
        end

        def to_xml
          Signature.sign(sign: sign) do |xml, signature|
            xml.LogoutResponse logout_response_options do
              xml.Issuer(issuer, xmlns: Namespaces::ASSERTION)
              signature.template(id)
              xml.Status do
                xml.StatusCode Value: status_code
              end
            end
          end
        end

        def build
          LogoutResponse.new(to_xml, request_id: request.id)
        end

        private

        def logout_response_options
          {
            xmlns: Namespaces::PROTOCOL,
            ID: "_#{id}",
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
