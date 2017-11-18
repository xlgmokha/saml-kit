module Saml
  module Kit
    class AuthenticationRequest < Document
      include Requestable
      validates_presence_of :acs_url, if: :expected_type?

      def initialize(xml)
        super(xml, name: "AuthnRequest")
      end

      def acs_url
        #if signed? && trusted?
          to_h[name]['AssertionConsumerServiceURL'] || registered_acs_url
        #else
          #registered_acs_url
        #end
      end

      def name_id_format
        to_h[name]['NameIDPolicy']['Format']
      end

      def response_for(user)
        Response::Builder.new(user, self).build
      end

      private

      def registered_acs_url
        return if provider.nil?
        acs_urls = provider.assertion_consumer_services
        return acs_urls.first[:location] if acs_urls.any?
      end

      class Builder
        attr_accessor :id, :now, :issuer, :acs_url, :name_id_format, :sign, :destination
        attr_accessor :version

        def initialize(configuration: Saml::Kit.configuration, sign: true)
          @id = SecureRandom.uuid
          @issuer = configuration.issuer
          @name_id_format = Namespaces::PERSISTENT
          @now = Time.now.utc
          @version = "2.0"
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
            Version: version,
            IssueInstant: now.utc.iso8601,
            Destination: destination,
          }
          options[:AssertionConsumerServiceURL] = acs_url if acs_url.present?
          options
        end
      end
    end
  end
end
