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

      private

      def parse_iso8601(value)
        DateTime.parse(value)
      rescue StandardError => error
        Saml::Kit.logger.error(error)
        Time.at(0).to_datetime
      end
    end
  end
end
