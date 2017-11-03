module Saml
  module Kit
    class AuthenticationRequest
      include ActiveModel::Validations
      validates_presence_of :content
      validate :must_have_valid_signature

      attr_reader :content

      def initialize(xml)
        @content = xml
        @hash = Hash.from_xml(@content)
      end

      def id
        @hash['AuthnRequest']['ID']
      end

      def acs_url
        @hash['AuthnRequest']['AssertionConsumerServiceURL']
      end

      def issuer
        @hash['AuthnRequest']['Issuer']
      end

      def to_xml
        @content
      end

      def response_for(user)
        Response::Builder.new(user, self).build
      end

      private

      def must_have_valid_signature
        return if to_xml.blank?

        xml = Saml::Kit::Xml.new(to_xml)
        xml.valid?
        xml.errors.each do |error|
          errors[:metadata] << error
        end
      end

      def error_message(key)
        I18n.translate(key, scope: "saml/kit.errors.#{descriptor_name}")
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
          options[:AssertionConsumerServiceURL] = acs_url if acs_url
          options
        end
      end
    end
  end
end
