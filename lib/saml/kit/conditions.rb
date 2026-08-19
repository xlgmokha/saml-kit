# frozen_string_literal: true

module Saml
  module Kit
    class Conditions
      include XmlParseable

      attr_reader :content

      def initialize(node)
        @to_nokogiri = node
        @content = node.to_s
      end

      def started_at
        parse_iso8601(at_xpath('./@NotBefore').try(:value))
      end

      def expired_at
        parse_iso8601(at_xpath('./@NotOnOrAfter').try(:value))
      end

      def audiences
        search('./saml:AudienceRestriction/saml:Audience').map(&:text)
      end

      # Returns true when the assertion is marked for single use.
      #
      # Core 2.5.1.5 obliges a relying party that retains assertions to honour
      # this. Enforcing it needs a cache of processed assertion ids, which is
      # the integrating application's responsibility, not this library's.
      def one_time_use?
        search('./saml:OneTimeUse').any?
      end
    end
  end
end
