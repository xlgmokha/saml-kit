module Saml
  module Kit
    module XsdValidatable
      def matches_xsd?(xsd)
        Dir.chdir(File.dirname(xsd)) do
          xsd = Nokogiri::XML::Schema(IO.read(xsd))
          document = Nokogiri::XML(to_xml)
          xsd.validate(document).each do |error|
            errors[:base] << error.message
          end
        end
      end

      def error_message(key)
        I18n.translate(key, scope: "saml/kit.errors.#{name}")
      end
    end
  end
end
