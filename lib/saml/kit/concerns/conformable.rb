# frozen_string_literal: true

module Saml
  module Kit
    # This module is responsible for the SAML profile conformance checks that
    # apply to any protocol message, and for the switch that turns a 1.6.0
    # warning into a 2.0.0 rejection.
    module Conformable
      extend ActiveSupport::Concern

      included do
        validate :must_match_destination
      end

      # The url at which this message was received.
      #
      # Only the application knows this, so it is unset by default and the
      # Destination check stays inert until it is assigned.
      attr_accessor :expected_destination

      private

      # Adds an error when a check is switched on, and otherwise warns that
      # 2.0.0 will start rejecting the document.
      #
      # Every conformance check routes through here so that 2.0.0 is a change
      # of defaults in Configuration and nothing else.
      #
      def reject_or_warn(attribute, key, subject, required:)
        return errors.add(attribute, error_message(key)) if required

        Saml::Kit.warn_conformance(subject)
      end

      # Core 3.2.2 obliges the recipient to check a Destination that is
      # present, and Bindings 3.4.5.2 and 3.5.5.2 require one on any signed
      # message delivered by POST or Redirect.
      #
      # Skipped when either side is unknown, matching how
      # `must_match_request_id` treats a nil request_id. Stripping a
      # Destination to reach that path invalidates the signature, and an
      # unsigned message has no authenticity to protect in the first place.
      def must_match_destination
        return if expected_destination.blank? || destination.blank?
        return if same_url?(destination, expected_destination)

        errors.add(:destination, error_message(:invalid_destination))
      end

      # Compares two urls the way the specs mean "matches": the same endpoint,
      # allowing only for spellings that are equivalent by definition.
      #
      # Deliberately conservative. Every additional normalisation widens what
      # an attacker can substitute for the expected endpoint.
      def same_url?(actual, expected)
        left = normalize_url(actual)
        left.present? && left == normalize_url(expected)
      end

      def normalize_url(value)
        return if value.blank?

        uri = URI.parse(value)
        [
          uri.scheme&.downcase,
          uri.host&.downcase,
          uri.port,
          uri.path.presence || '/',
          uri.query,
          uri.fragment,
        ]
      rescue URI::InvalidURIError => error
        Saml::Kit.logger.error(error)
        nil
      end
    end
  end
end
