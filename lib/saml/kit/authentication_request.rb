module Saml
  module Kit
    class AuthenticationRequest
      PROTOCOL_XSD = File.expand_path("./xsd/saml-schema-protocol-2.0.xsd", File.dirname(__FILE__)).freeze
      include XsdValidatable
      include ActiveModel::Validations

      validates_presence_of :content
      validates_presence_of :acs_url, if: :login_request?
      validate :must_be_request
      validate :must_have_valid_signature
      validate :must_be_registered
      validate :must_match_xsd

      attr_reader :content, :name

      def initialize(xml)
        @content = xml
        @name = "AuthnRequest"
        @hash = Hash.from_xml(@content)
      end

      def id
        to_h[name]['ID']
      end

      def acs_url
        to_h[name]['AssertionConsumerServiceURL'] || registered_acs_url
      end

      def issuer
        to_h[name]['Issuer']
      end

      def name_id_format
        to_h[name]['NameIDPolicy']['Format']
      end

      def certificate
        to_h[name]['Signature']['KeyInfo']['X509Data']['X509Certificate']
      end

      def fingerprint
        Fingerprint.new(certificate)
      end

      def signed?
        to_h[name]['Signature'].present?
      end

      def to_h
        @hash
      end

      def to_xml
        @content
      end

      def serialize
        Saml::Kit::Content.encode_raw_saml(to_xml)
      end

      def response_for(user)
        Response::Builder.new(user, self).build
      end

      def trusted?
        return false if provider.nil?
        return false unless signed?
        provider.matches?(fingerprint, use: :signing)
      end

      def provider
        registry.metadata_for(issuer)
      end

      private

      def registered_acs_url
        return if provider.nil?
        acs_urls = provider.assertion_consumer_services
        return acs_urls.first[:location] if acs_urls.any?
      end

      def registry
        Saml::Kit.configuration.registry
      end

      def must_be_registered
        return unless login_request?
        if provider.nil?
          errors[:service_provider] << error_message(:unregistered)
          return
        end
        return if trusted?
        errors[:fingerprint] << error_message(:invalid_fingerprint)
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

      def must_match_xsd
        matches_xsd?(PROTOCOL_XSD)
      end

      def login_request?
        return false if to_xml.blank?
        @hash[name].present?
      end

      class Builder
        attr_accessor :id, :issued_at, :issuer, :acs_url, :name_id_format
        attr_reader :sign

        def initialize(configuration = Saml::Kit.configuration, sign: true)
          @id = SecureRandom.uuid
          @issued_at = Time.now.utc
          @issuer = configuration.issuer
          @name_id_format = Namespaces::PERSISTENT
          @sign = sign
        end

        def to_xml
          Signature.sign(id, sign: sign) do |xml, signature|
            xml.tag!('samlp:AuthnRequest', request_options) do
              xml.tag!('saml:Issuer', issuer)
              signature.template(xml)
              xml.tag!('samlp:NameIDPolicy', Format: name_id_format)
            end
          end
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
            IssueInstant: issued_at.utc.iso8601,
          }
          options[:AssertionConsumerServiceURL] = acs_url if acs_url.present?
          options
        end
      end
    end
  end
end
