module Saml
  module Kit
    class Assertion
      include ActiveModel::Validations
      include Translatable
      XPATH = [
        '/samlp:Response/saml:Assertion',
        '/samlp:Response/saml:EncryptedAssertion'
      ].join('|')

      validate :must_be_decryptable
      validate :must_match_issuer, if: :decryptable?
      validate :must_be_active_session, if: :decryptable?
      validate :must_have_valid_signature, if: :decryptable?
      attr_reader :name
      attr_accessor :occurred_at

      def initialize(node, configuration: Saml::Kit.configuration, private_keys: [])
        @name = 'Assertion'
        @node = node
        @xml_hash = hash_from(node)['Response'] || {}
        @configuration = configuration
        @occurred_at = Time.current
        decrypt!(::Xml::Kit::Decryption.new(
                   private_keys: (
                     configuration.private_keys(use: :encryption) + private_keys
                   ).uniq
        ))
      end

      def issuer
        at_xpath('./saml:Issuer').try(:text)
      end

      def name_id
        assertion.fetch('Subject', {}).fetch('NameID', nil)
      end

      def signed?
        signature.present?
      end

      def signature
        @signature ||= Signature.new(at_xpath('./ds:Signature'))
      end

      def expired?(now = occurred_at)
        now > expired_at
      end

      def active?(now = occurred_at)
        drifted_started_at = started_at - configuration.clock_drift.to_i.seconds
        now > drifted_started_at && !expired?(now)
      end

      def attributes
        @attributes ||=
          begin
            attrs = assertion.fetch('AttributeStatement', {}).fetch('Attribute', [])
            items = if attrs.is_a? Hash
                      [[attrs['Name'], attrs['AttributeValue']]]
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
      rescue StandardError => error
        Saml::Kit.logger.error(error)
        []
      end

      def encrypted?
        @xml_hash.fetch('EncryptedAssertion', nil).present?
      end

      def decryptable?
        return true unless encrypted?
        !@cannot_decrypt
      end

      def present?
        assertion.present?
      end

      def to_xml(pretty: false)
        pretty ? @node.to_xml(indent: 2) : @node.to_s
      end

      private

      attr_reader :configuration

      def assertion
        @assertion ||=
          begin
            result = (hash_from(@node)['Response'] || {})['Assertion']
            return result if result.is_a?(Hash)
            {}
          end
      end

      def decrypt!(decryptor)
        return unless encrypted?

        encrypted_assertion = @node.at_xpath('./xmlenc:EncryptedData', Saml::Kit::Document::NAMESPACES)
        @node = decryptor.decrypt_node(encrypted_assertion)
      rescue Xml::Kit::DecryptionError => error
        @cannot_decrypt = true
        Saml::Kit.logger.error(error)
      end

      def parse_date(value)
        DateTime.parse(value)
      rescue StandardError => error
        Saml::Kit.logger.error(error)
        Time.at(0).to_datetime
      end

      def must_match_issuer
        return if audiences.include?(configuration.entity_id)
        errors[:audience] << error_message(:must_match_issuer)
      end

      def must_be_active_session
        return if active?
        errors[:base] << error_message(:expired)
      end

      def must_have_valid_signature
        return if !signed? || signature.valid?

        signature.errors.each do |attribute, message|
          errors.add(attribute, message)
        end
      end

      def must_be_decryptable
        errors.add(:base, error_message(:cannot_decrypt)) unless decryptable?
      end

      def at_xpath(xpath)
        @node.at_xpath(xpath, Saml::Kit::Document::NAMESPACES)
      end

      def hash_from(node)
        return {} if node.nil?
        Hash.from_xml(node.document.root.to_s) || {}
      end
    end
  end
end
