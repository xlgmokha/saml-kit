# frozen_string_literal: true

module Saml
  module Kit
    # This module is responsible for validating
    # xml documents against the SAML XSD's
    module XsdValidatable
      # @!visibility private
      def matches_xsd?(xsd)
        Dir.chdir(File.dirname(xsd)) do
          xsd = Nokogiri::XML::Schema(IO.read(xsd))
          xsd.validate(to_nokogiri).each do |error|
            errors[:base] << error.message
          end
        end
      end
    end
  end
end
