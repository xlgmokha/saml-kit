module Saml
  module Kit
    module Builders
      class LogoutRequest
        attr_accessor :id, :destination, :issuer, :name_id_format, :now
        attr_accessor :sign, :version
        attr_reader :user

        def initialize(user, configuration: Saml::Kit.configuration, sign: true)
          @user = user
          @id = "_#{SecureRandom.uuid}"
          @issuer = configuration.issuer
          @name_id_format = Saml::Kit::Namespaces::PERSISTENT
          @now = Time.now.utc
          @version = "2.0"
          @sign = sign
        end

        def to_xml
          Signature.sign(sign: sign) do |xml, signature|
            xml.instruct!
            xml.LogoutRequest logout_request_options do
              xml.Issuer({ xmlns: Namespaces::ASSERTION }, issuer)
              signature.template(id)
              xml.NameID name_id_options, user.name_id_for(name_id_format)
            end
          end
        end

        def build
          Saml::Kit::LogoutRequest.new(to_xml)
        end

        private

        def logout_request_options
          {
            ID: id,
            Version: version,
            IssueInstant: now.utc.iso8601,
            Destination: destination,
            xmlns: Namespaces::PROTOCOL,
          }
        end

        def name_id_options
          {
            Format: name_id_format,
            xmlns: Namespaces::ASSERTION,
          }
        end
      end
    end
  end
end
