# frozen_string_literal: true

module Saml
  module Kit
    # This module is responsible for the Web Browser SSO profile's
    # requirements on an Assertion.
    #
    # Profiles 4.1.4.2 states them in terms of the assertion carrying a bearer
    # subject confirmation -- including the AudienceRestriction requirement --
    # which is why they live together here.
    module BearerConfirmable
      extend ActiveSupport::Concern

      included do
        validate :must_match_issuer, if: :decryptable?
        validate :must_have_audience, if: :decryptable?
        validate :must_have_bearer_confirmation, if: :decryptable?
        validate :must_not_be_expired_by_confirmation, if: :decryptable?
        validate :must_match_recipient, if: :decryptable?
        validate :must_have_authn_statement, if: :decryptable?
      end

      # The assertion consumer service url at which this assertion was
      # received. Only the application knows it, so the Recipient check stays
      # inert until it is assigned.
      attr_accessor :expected_recipient

      # Returns each SubjectConfirmation in the Subject.
      def subject_confirmations
        @subject_confirmations ||=
          search('./saml:Subject/saml:SubjectConfirmation').map do |node|
            SubjectConfirmation.new(node)
          end
      end

      # Returns the bearer SubjectConfirmation, or nil when there is none.
      def bearer_confirmation
        subject_confirmations.find(&:bearer?)
      end

      private

      def must_match_issuer
        return if audiences.empty? || audiences.include?(configuration.entity_id)

        errors.add(:audience, error_message(:must_match_issuer))
      end

      def must_have_audience
        return if audiences.any?

        reject_or_warn(
          :audience, :must_have_audience,
          'An Assertion with no AudienceRestriction',
          required: configuration.audience_required
        )
      end

      def must_have_bearer_confirmation
        return if conformant_confirmation?

        reject_or_warn(
          :base, :missing_subject_confirmation,
          'An Assertion with no conformant bearer SubjectConfirmation',
          required: configuration.subject_confirmation_required
        )
      end

      # Profiles 4.1.4.2 requires a bearer SubjectConfirmationData carrying a
      # NotOnOrAfter, and forbids a NotBefore on it.
      def conformant_confirmation?
        confirmation = bearer_confirmation
        return false if confirmation.nil?

        confirmation.expired_at.present? && confirmation.started_at.nil?
      end

      def must_not_be_expired_by_confirmation
        confirmation = bearer_confirmation
        return if confirmation.nil? || !confirmation.expired?(occurred_at)

        reject_or_warn(
          :base, :expired_subject_confirmation,
          'An Assertion with an expired bearer SubjectConfirmation',
          required: configuration.subject_confirmation_required
        )
      end

      # Profiles 4.1.4.3 obliges the service provider to verify the Recipient
      # against the assertion consumer service url it was delivered to.
      def must_match_recipient
        return if expected_recipient.blank? || bearer_confirmation.nil?
        return if same_url?(bearer_confirmation.recipient, expected_recipient)

        errors.add(:recipient, error_message(:invalid_recipient))
      end

      def must_have_authn_statement
        return if at_xpath('./saml:AuthnStatement').present?

        reject_or_warn(
          :base, :missing_authn_statement,
          'An Assertion with no AuthnStatement',
          required: configuration.authn_statement_required
        )
      end
    end
  end
end
