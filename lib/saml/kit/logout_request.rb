module Saml
  module Kit
    class LogoutRequest
      PROTOCOL_XSD = File.expand_path("./xsd/saml-schema-protocol-2.0.xsd", File.dirname(__FILE__)).freeze
      include XsdValidatable
      include ActiveModel::Validations
      validates_presence_of :content
      validates_presence_of :single_logout_service, if: :logout_request?
      validate :must_be_request
      validate :must_have_valid_signature
      validate :must_be_registered
      validate :must_match_xsd

      attr_reader :content, :name

      def initialize(xml)
        @content = xml
        @name = "LogoutRequest"
        @xml_hash = Hash.from_xml(xml)
      end

      def issuer
        to_h[name]['Issuer']
      end

      def issue_instant
        to_h[name]['IssueInstant']
      end

      def version
        to_h[name]['Version']
      end

      def destination
        to_h[name]['Destination']
      end

      def name_id
        to_h[name]['NameID']
      end

      def single_logout_service
        return if provider.nil?
        urls = provider.single_logout_services
        return urls.first[:location] if urls.any?
      end

      def to_h
        @xml_hash
      end

      def to_xml
        @content
      end

      def trusted?
        return false if provider.nil?
        return false unless signed?
        provider.matches?(fingerprint, use: :signing)
      end

      def provider
        registry.metadata_for(issuer)
      end

      def certificate
        return nil unless signed?
        to_h[name]['Signature']['KeyInfo']['X509Data']['X509Certificate']
      end

      def fingerprint
        return nil unless signed?
        Fingerprint.new(certificate)
      end

      def signed?
        to_h[name]['Signature'].present?
      end

      private

      def registry
        Saml::Kit.configuration.registry
      end

      def must_have_valid_signature
        return if to_xml.blank?

        xml = Saml::Kit::Xml.new(to_xml)
        xml.valid?
        xml.errors.each do |error|
          errors[:base] << error
        end
      end

      def must_be_request
        return if to_h.nil?

        errors[:base] << error_message(:invalid) unless logout_request?
      end

      def must_be_registered
        return unless logout_request?
        if provider.nil?
          errors[:provider] << error_message(:unregistered)
          return
        end
        return if trusted?
        errors[:fingerprint] << error_message(:invalid_fingerprint)
      end

      def must_match_xsd
        matches_xsd?(PROTOCOL_XSD)
      end

      def logout_request?
        return false if to_xml.blank?
        to_h[name].present?
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
            Version: "2.0",
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
