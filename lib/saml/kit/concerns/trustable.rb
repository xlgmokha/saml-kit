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
        validate :must_be_signed, if: :signature_required?
        validate :must_be_trusted
      end

      # Returns true when this document must carry a signature to be valid.
      def signature_required?
        configuration.signature_required && signature_required_by_type?
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

      # Whether a document of this type is worthless unless signed.
      #
      # A request may legitimately arrive unsigned, which is what
      # `WantAuthnRequestsSigned="false"` means, so the default is false. A
      # document that asserts an identity carries no authenticity guarantee at
      # all when unsigned, so Response and Assertion override this.
      def signature_required_by_type?
        false
      end

      def must_be_signed
        return unless expected_type?
        return if signature_covers_document?

        errors.add(:base, error_message(:unsigned))
      end

      # Whether a signature exists over the content this document asserts.
      # Response overrides this, because a signature on either the Response or
      # the Assertion covers the identity being asserted.
      def signature_covers_document?
        signed?
      end

      # The trust counterpart of `signature_covers_document?`. Kept separate
      # from the public `trusted?`, which answers the narrower question of
      # whether *this* element's own signature is trusted.
      def signature_trusted?
        trusted?
      end

      def must_be_trusted
        return if signature_trusted?
        return if !signature_required? && provider.present? && !signed?

        errors.add(:fingerprint, error_message(:invalid_fingerprint))
      end
    end
  end
end
