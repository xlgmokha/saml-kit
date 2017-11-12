module Saml
  module Kit
    class LogoutRequest
      class Builder
        attr_accessor :id, :destination, :issuer, :name_id_format, :now
        attr_reader :user

        def initialize(user, configuration: Saml::Kit.configuration)
          @user = user
          @id = SecureRandom.uuid
          @issuer = configuration.issuer
          @name_id_format = Saml::Kit::Namespaces::PERSISTENT
          @now = Time.now.utc
        end

        def to_xml
          xml = ::Builder::XmlMarkup.new
          xml.instruct!
          xml.LogoutRequest logout_request_options do
            xml.Issuer issuer
            xml.NameID name_id_options, user.name_id_for(self)
          end
          xml.target!
        end

        private

        def logout_request_options
          {
            ID: id,
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
