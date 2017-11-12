module Saml
  module Kit
    class LogoutRequest
      def initialize(xml)
        @xml = xml
      end

      def to_xml
        @xml
      end

      class Builder
        attr_accessor :id, :destination, :issuer, :name_id_format, :now
        attr_accessor :sign
        attr_reader :user

        def initialize(user, configuration: Saml::Kit.configuration)
          @user = user
          @id = SecureRandom.uuid
          @issuer = configuration.issuer
          @name_id_format = Saml::Kit::Namespaces::PERSISTENT
          @now = Time.now.utc
          @sign = true
        end

        def to_xml
          Signature.sign(id, sign: sign) do |xml, signature|
            xml.instruct!
            xml.LogoutRequest logout_request_options do
              xml.Issuer issuer
              signature.template(xml)
              xml.NameID name_id_options, user.name_id_for(self)
            end
          end
        end

        def build
          Saml::Kit::LogoutRequest.new(to_xml)
        end

        private

        def logout_request_options
          {
            ID: "_#{id}",
            Version: "2.0",
            IssueInstant: now.utc.iso8601,
            Destination: destination,
          }
        end

        def name_id_options
          {
            Format: name_id_format,
          }
        end
      end
    end
  end
end
