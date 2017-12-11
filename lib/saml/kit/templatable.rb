module Saml
  module Kit
    module Templatable
      def template_name
        "#{self.class.name.split("::").last.underscore}.builder"
      end

      def template_path
        File.join(File.expand_path(File.dirname(__FILE__)), "builders/templates/#{template_name}")
      end

      def template
        Tilt.new(template_path)
      end

      def to_xml(xml: ::Builder::XmlMarkup.new)
        signature = Saml::Kit::Signature.new(
          xml,
          configuration: configuration,
          sign: sign
        )
        signature.apply_to(
          template.render(self, xml: xml, signature: signature)
        )
      end
    end
  end
end
