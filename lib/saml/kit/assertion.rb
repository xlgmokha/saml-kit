module Saml
  module Kit
    class Assertion
      def initialize(xml)
        @xml = xml
        @xml_hash = Hash.from_xml(xml) || {}
      end

      def name_id
        assertion.fetch('Subject', {}).fetch('NameID', nil)
      end

      def signed?
        assertion.fetch('Signature', nil).present?
      end

      def attributes
        @attributes ||=
          begin
            attrs = assertion.fetch('AttributeStatement', {}).fetch('Attribute', [])
            items = if attrs.is_a? Hash
                      [[attrs["Name"], attrs["AttributeValue"]]]
                    else
                      attrs.map { |item| [item['Name'], item['AttributeValue']] }
                    end
            Hash[items].with_indifferent_access
          end
      end

      def started_at
        parse_date(assertion.fetch('Conditions', {}).fetch('NotBefore', nil))
      end

      def expired_at
        parse_date(assertion.fetch('Conditions', {}).fetch('NotOnOrAfter', nil))
      end

      def certificate
        assertion.fetch('Signature', {}).fetch('KeyInfo', {}).fetch('X509Data', {}).fetch('X509Certificate', nil)
      end

      def audiences
        Array(assertion['Conditions']['AudienceRestriction']['Audience'])
      rescue => error
        Saml::Kit.logger.error(error)
        []
      end

      private

      def encrypted?
        @xml_hash['Response']['EncryptedAssertion'].present?
      end

      def assertion
        if encrypted?
          decrypted = XmlDecryption.new.decrypt(@xml_hash['Response']['EncryptedAssertion'])
          Saml::Kit.logger.debug(decrypted)
          Hash.from_xml(decrypted)['Assertion']
        else
          @xml_hash['Response'].fetch('Assertion', {})
        end
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
