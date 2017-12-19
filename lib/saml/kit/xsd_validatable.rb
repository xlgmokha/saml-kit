module Saml
  module Kit
    module XsdValidatable
      # @!visibility private
      def matches_xsd?(xsd)
        Dir.chdir(File.dirname(xsd)) do
          xsd = Nokogiri::XML::Schema(IO.read(xsd))
          document = Nokogiri::XML(to_xml)
          xsd.validate(document).each do |error|
            errors[:base] << error.message
          end
        end
      end
    end
  end
end
