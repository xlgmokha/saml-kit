module Saml
  module Kit
    module XmlTemplatable
      include ::Xml::Kit::Templatable

      def template_path
        root_path = File.expand_path(File.dirname(__FILE__))
        template_name = "#{self.class.name.split("::").last.underscore}.builder"
        File.join(root_path, "builders/templates/", template_name)
      end
    end
  end
end
