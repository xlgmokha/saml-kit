module Saml
  module Kit
    class Template
      attr_reader :target

      def initialize(target)
        @target = target
      end

      def to_xml(xml: ::Builder::XmlMarkup.new)
        signature = Saml::Kit::Signature.new(xml, configuration: target.configuration, sign: target.sign)
        signature.apply_to(template.render(target, xml: xml, signature: signature))
      end

      private

      def template_name
        "#{target.class.name.split("::").last.underscore}.builder"
      end

      def template_path
        File.join(File.expand_path(File.dirname(__FILE__)), "builders/templates/#{template_name}")
      end

      def template
        Tilt.new(template_path)
      end
    end
  end
end
