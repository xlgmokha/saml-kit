# frozen_string_literal: true

module Saml
  module Kit
    # This module is responsible for validating
    # xml documents against the SAML XSD's
    module XsdValidatable
      PROTOCOL_XSD = File.expand_path(
        '../xsd/saml-schema-protocol-2.0.xsd', File.dirname(__FILE__)
      ).freeze

      METADATA_XSD = File.expand_path(
        '../xsd/saml-schema-metadata-2.0.xsd', File.dirname(__FILE__)
      ).freeze

      # @!visibility private
      def matches_xsd?(xsd)
        return unless to_nokogiri.present?

        Dir.chdir(File.dirname(xsd)) do
          xsd = Nokogiri::XML::Schema(IO.read(xsd))
          xsd.validate(to_nokogiri.document).each do |error|
            errors[:base] << error.message
          end
        end
      end
    end
  end
end
