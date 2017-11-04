module Saml
  module Kit
    class AuthenticationRequest
      include ActiveModel::Validations
      validates_presence_of :content
      validates_presence_of :acs_url, if: :login_request?
      validate :must_be_request
      validate :must_have_valid_signature
      validate :must_be_registered_service_provider

      attr_reader :content, :name

      def initialize(xml)
        @content = xml
        @name = "AuthnRequest"
        @hash = Hash.from_xml(@content)
      end

      def id
        @hash[name]['ID']
      end

      def acs_url
        @hash[name]['AssertionConsumerServiceURL'] || registered_acs_url
      end

      def issuer
        @hash[name]['Issuer']
      end

      def certificate
        @hash[name]['Signature']['KeyInfo']['X509Data']['X509Certificate']
      end

      def fingerprint
        Fingerprint.new(certificate)
      end

      def to_xml
        @content
      end

      def response_for(user)
        Response::Builder.new(user, self).build
      end

      private

      def registered_acs_url
        acs_urls = service_provider.assertion_consumer_services
        return acs_urls.first[:location] if acs_urls.any?
      end

      def service_provider
        registry.metadata_for(issuer)
      end

      def registry
        Saml::Kit.configuration.registry
      end

      def must_be_registered_service_provider
        return unless login_request?
        return if service_provider.matches?(fingerprint, use: "signing")

        errors[:base] << error_message(:invalid)
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
        return if @hash.nil?

        errors[:base] << error_message(:invalid) unless login_request?
      end

      def login_request?
        return false if to_xml.blank?
        @hash[name].present?
      end

      def error_message(key)
        I18n.translate(key, scope: "saml/kit.errors.#{name}")
      end

      class Builder
        attr_accessor :id, :issued_at, :issuer, :acs_url

        def initialize(configuration = Saml::Kit.configuration)
          @id = SecureRandom.uuid
          @issued_at = Time.now.utc
          @issuer = configuration.issuer
        end

        def to_xml(xml = ::Builder::XmlMarkup.new)
          signature = Signature.new(id)
          xml.tag!('samlp:AuthnRequest', request_options) do
            signature.template(xml)
            xml.tag!('saml:Issuer', issuer)
            xml.tag!('samlp:NameIDPolicy', Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
          end
          signature.finalize(xml)
        end

        def build
          AuthenticationRequest.new(to_xml)
        end

        private

        def request_options
          options = {
            "xmlns:samlp" => Namespaces::PROTOCOL,
            "xmlns:saml" => Namespaces::ASSERTION,
            ID: "_#{id}",
            Version: "2.0",
            IssueInstant: issued_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
          }
          options[:AssertionConsumerServiceURL] = acs_url if acs_url.present?
          options
        end
      end
    end
  end
end
