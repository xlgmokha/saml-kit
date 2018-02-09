module Saml
  module Kit
    class Assertion
      include ActiveModel::Validations
      include Translatable

      validate :must_match_issuer
      validate :must_be_active_session
      attr_reader :name

      def initialize(xml_hash, configuration:)
        @name = "Assertion"
        @xml_hash = xml_hash
        @configuration = configuration
      end

      def issuer
        assertion.fetch('Issuer')
      end

      def name_id
        assertion.fetch('Subject', {}).fetch('NameID', nil)
      end

      def signed?
        signature.present?
      end

      def signature
        xml_hash = assertion.fetch('Signature', nil)
        xml_hash ? Signature.new(xml_hash) : nil
      end

      def expired?(now = Time.current)
        now > expired_at
      end

      def active?(now = Time.current)
        now > configuration.clock_drift.seconds.before(started_at) && !expired?
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

      def audiences
        Array(assertion['Conditions']['AudienceRestriction']['Audience'])
      rescue => error
        Saml::Kit.logger.error(error)
        []
      end

      def encrypted?
        @xml_hash.fetch('Response', {}).fetch('EncryptedAssertion', nil).present?
      end

      private

      attr_reader :configuration

      def assertion
        @assertion ||=
          if encrypted?
            private_keys = configuration.private_keys(use: :encryption)
            decryptor = ::Xml::Kit::Decryption.new(private_keys: private_keys)
            decrypted = decryptor.decrypt_hash(@xml_hash['Response']['EncryptedAssertion'])
            Saml::Kit.logger.debug(decrypted)
            Hash.from_xml(decrypted)['Assertion']
          else
            result = @xml_hash.fetch('Response', {}).fetch('Assertion', {})
            return result if result.is_a?(Hash)

            errors[:assertion] << error_message(:must_contain_single_assertion)
            {}
          end
      end

      def parse_date(value)
        DateTime.parse(value)
      rescue => error
        Saml::Kit.logger.error(error)
        Time.at(0).to_datetime
      end

      def must_match_issuer
        unless audiences.include?(configuration.entity_id)
          errors[:audience] << error_message(:must_match_issuer)
        end
      end

      def must_be_active_session
        return if active?
        errors[:base] << error_message(:expired)
      end
    end
  end
end
