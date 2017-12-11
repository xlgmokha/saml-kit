module Saml
  module Kit
    module Templatable
      def to_xml(xml: ::Builder::XmlMarkup.new)
        Template.new(self).to_xml(xml: xml)
      end
    end
  end
end
