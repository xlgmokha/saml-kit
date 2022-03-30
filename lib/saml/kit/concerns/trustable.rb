# frozen_string_literal: true

module Saml
  module Kit
    # This module is responsible for
    # validating the trustworthiness
    # of a saml document.
    module Trustable
      extend ActiveSupport::Concern

      included do
        validate :must_have_valid_signature, unless: :signature_verified
        validate :must_be_registered
        validate :must_be_trusted
      end

      # Returns true when the document has an embedded XML Signature or has
      # been verified externally.
      def signed?
        signature_verified || signature.present?
      end

      # @!visibility private
      def signature
        @signature ||= Signature.new(at_xpath("/samlp:#{name}/ds:Signature"))
      end

      # Returns true when documents is signed and the signing certificate
      # belongs to a known service entity.
      def trusted?
        return true if signature_verified
        return false unless signed?

        signature.trusted?(provider)
      end

      # @!visibility private
      def provider
        registry.metadata_for(issuer)
      end

      # @!visibility private
      def signature_verified!
        @signature_verified = true
      end

      private

      attr_reader :signature_verified

      def must_have_valid_signature
        return if to_xml.blank?
        return unless signature.present?

        signature.valid?
        signature.each_error do |attribute, error|
          errors.add(attribute, error)
        end
      end

      def must_be_registered
        return unless expected_type?
        return if provider.present?

        errors.add(:provider, error_message(:unregistered))
      end

      def must_be_trusted
        return if trusted?
        return if provider.present? && !signed?

        errors.add(:fingerprint, error_message(:invalid_fingerprint))
      end
    end
  end
end
