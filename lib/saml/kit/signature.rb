# frozen_string_literal: true

module Saml
  module Kit
    class Signature
      include ActiveModel::Validations
      include Translatable

      validate :validate_signature
      validate :validate_certificate

      attr_reader :name

      def initialize(node)
        @name = 'Signature'
        @node = node
      end

      # Returns the embedded X509 Certificate
      def certificate
        value = at_xpath('./ds:KeyInfo/ds:X509Data/ds:X509Certificate').try(:text)
        return if value.nil?
        ::Xml::Kit::Certificate.new(value, use: :signing)
      end

      # Returns true when the fingerprint of the certificate matches one of the certificates registered in the metadata.
      def trusted?(metadata)
        return false if metadata.nil?
        metadata.matches?(certificate.fingerprint, use: :signing)
      end

      def digest_value
        at_xpath('./ds:SignedInfo/ds:Reference/ds:DigestValue').try(:text)
      end

      def expected_digest_value
        digests = dsignature.references.map do |x|
          Base64.encode64(x.calculate_digest_value).chomp
        end
        digests.count > 1 ? digests : digests[0]
      end

      def digest_method
        at_xpath('./ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm').try(:value)
      end

      def signature_value
        at_xpath('./ds:SignatureValue').try(:text)
      end

      def signature_method
        at_xpath('./ds:SignedInfo/ds:SignatureMethod/@Algorithm').try(:value)
      end

      def canonicalization_method
        at_xpath('./ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm').try(:value)
      end

      def transforms
        node.search('./ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform/@Algorithm', Saml::Kit::Document::NAMESPACES).try(:map, &:value)
      end

      # Returns the XML Hash.
      def to_h
        @xml_hash ||= present? ? Hash.from_xml(to_xml)['Signature'] : {}
      end

      def present?
        node.present?
      end

      def to_xml(pretty: false)
        pretty ? node.to_xml(indent: 2) : node.to_s
      end

      private

      attr_reader :node

      def validate_signature
        return errors.add(:base, error_message(:empty)) if certificate.nil?
        return if dsignature.valid?(certificate.x509)

        dsignature.errors.each do |attribute|
          errors.add(attribute, error_message(attribute))
        end
      rescue Xmldsig::SchemaError => error
        errors.add(:base, error.message)
      end

      def validate_certificate(now = Time.now.utc)
        return unless certificate.present?
        return if certificate.active?(now)

        message = error_message(
          :certificate,
          not_before: certificate.not_before,
          not_after: certificate.not_after
        )
        errors.add(:certificate, message)
      end

      def at_xpath(xpath)
        return nil unless node
        node.at_xpath(xpath, Saml::Kit::Document::NAMESPACES)
      end

      def dsignature
        @dsignature ||= Xmldsig::Signature.new(node, 'ID=$uri or @Id')
      end
    end
  end
end
