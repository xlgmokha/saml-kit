module Saml
  module Kit
    class LogoutRequest
      class Builder
        attr_accessor :destination, :id, :now

        def initialize
          @id = SecureRandom.uuid
          @now = Time.now
        end

        def to_xml(xml = ::Builder::XmlMarkup.new)
          xml.LogoutRequest logout_request_options do
          end
        end

        private

        def logout_request_options
          {
            "xmlns" => Saml::Kit::Namespaces::PROTOCOL,
            Destination: destination,
            ID: id,
            IssueInstant: now.utc.iso8601,
            Version: "2.0",
          }
        end
      end
    end
  end
end
