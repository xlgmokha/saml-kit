module Saml
  module Kit
    class LogoutRequest < Document
      include Requestable
      validates_presence_of :single_logout_service, if: :expected_type?
      validate :must_be_registered

      def initialize(xml)
        super(xml, name: "LogoutRequest")
      end

      def issue_instant
        to_h[name]['IssueInstant']
      end

      def name_id
        to_h[name]['NameID']
      end

      def single_logout_service
        return if provider.nil?
        urls = provider.single_logout_services
        return urls.first[:location] if urls.any?
      end

      def response_for(user)
        LogoutResponse::Builder.new(user, self).build
      end

      private

      def must_be_registered
        return unless expected_type?
        if provider.nil?
          errors[:provider] << error_message(:unregistered)
          return
        end
        return if trusted?
        errors[:fingerprint] << error_message(:invalid_fingerprint)
      end


      class Builder
        attr_accessor :id, :destination, :issuer, :name_id_format, :now
        attr_accessor :sign, :version
        attr_reader :user

        def initialize(user, configuration: Saml::Kit.configuration, sign: true)
          @user = user
          @id = SecureRandom.uuid
          @issuer = configuration.issuer
          @name_id_format = Saml::Kit::Namespaces::PERSISTENT
          @now = Time.now.utc
          @version = "2.0"
          @sign = sign
        end

        def to_xml
          Signature.sign(id, sign: sign) do |xml, signature|
            xml.instruct!
            xml.LogoutRequest logout_request_options do
              xml.Issuer({ xmlns: Namespaces::ASSERTION }, issuer)
              signature.template(xml)
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
            ID: "_#{id}",
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
