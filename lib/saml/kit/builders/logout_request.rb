module Saml
  module Kit
    module Builders
      # {include:file:spec/saml/builders/logout_request_spec.rb}
      class LogoutRequest
        include XmlTemplatable
        attr_accessor :id, :destination, :issuer, :name_id_format, :now
        attr_accessor :version
        attr_reader :user, :configuration

        def initialize(user, configuration: Saml::Kit.configuration)
          @configuration = configuration
          @user = user
          @id = "_#{SecureRandom.uuid}"
          @issuer = configuration.issuer
          @name_id_format = Saml::Kit::Namespaces::PERSISTENT
          @now = Time.now.utc
          @version = "2.0"
        end

        def build
          Saml::Kit::LogoutRequest.new(to_xml, configuration: configuration)
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
