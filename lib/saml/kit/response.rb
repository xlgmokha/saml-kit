module Saml
  module Kit
    class Response < Document
      include Respondable

      validate :must_be_active_session
      validate :must_match_issuer

      def initialize(xml, request_id: nil)
        @request_id = request_id
        super(xml, name: "Response")
      end

      def name_id
        assertion.fetch('Subject', {}).fetch('NameID', nil)
      end

      def [](key)
        attributes[key]
      end

      def attributes
        @attributes ||= Hash[
          assertion.fetch('AttributeStatement', {}).fetch('Attribute', []).map do |item|
            [item['Name'].to_sym, item['AttributeValue']]
          end
        ].with_indifferent_access
      end

      def started_at
        parse_date(assertion.fetch('Conditions', {}).fetch('NotBefore', nil))
      end

      def expired_at
        parse_date(assertion.fetch('Conditions', {}).fetch('NotOnOrAfter', nil))
      end

      def expired?
        Time.current > expired_at
      end

      def active?
        Time.current > started_at && !expired?
      end

      def encrypted?
        to_h[name]['EncryptedAssertion'].present?
      end

      def assertion
        @assertion =
          begin
            if encrypted?
              decrypted = Cryptography.new.decrypt(to_h.fetch(name, {}).fetch('EncryptedAssertion', {}))
              Saml::Kit.logger.debug(decrypted)
              Hash.from_xml(decrypted)['Assertion']
            else
              to_h.fetch(name, {}).fetch('Assertion', {})
            end
          end
      end

      def signed?
        super || assertion.fetch('Signature', nil).present?
      end

      def certificate
        super || assertion.fetch('Signature', {}).fetch('KeyInfo', {}).fetch('X509Data', {}).fetch('X509Certificate', nil)
      end

      private

      def must_be_active_session
        return unless expected_type?
        return unless success?
        errors[:base] << error_message(:expired) unless active?
      end

      def must_match_issuer
        return unless expected_type?
        return unless success?

        unless audiences.include?(Saml::Kit.configuration.issuer)
          errors[:audience] << error_message(:must_match_issuer)
        end
      end

      def audiences
        Array(assertion['Conditions']['AudienceRestriction']['Audience'])
      rescue => error
        Saml::Kit.logger.error(error)
        []
      end

      def parse_date(value)
        DateTime.parse(value)
      rescue => error
        Saml::Kit.logger.error(error)
        Time.at(0).to_datetime
      end
    end
  end
end
