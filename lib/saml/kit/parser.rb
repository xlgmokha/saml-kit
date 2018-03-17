# frozen_string_literal: true
#
module Saml
  module Kit
    class Parser
      # Creates a `{Saml::Kit::Metadata}` object from a raw XML [String].
      #
      # @param content [String] the raw metadata XML.
      # @return [Saml::Kit::Metadata] the metadata document or subclass.
      def map_from(content)
        document = Nokogiri::XML(content)
        return unless document.at_xpath('/md:EntityDescriptor', XmlParseable::NAMESPACES)

        xpath = '/md:EntityDescriptor/md:SPSSODescriptor'
        sp = document.at_xpath(xpath, XmlParseable::NAMESPACES)
        xpath = '/md:EntityDescriptor/md:IDPSSODescriptor'
        idp = document.at_xpath(xpath, XmlParseable::NAMESPACES)
        if sp && idp
          Saml::Kit::CompositeMetadata.new(content)
        elsif sp
          Saml::Kit::ServiceProviderMetadata.new(content)
        elsif idp
          Saml::Kit::IdentityProviderMetadata.new(content)
        end
      end
    end
  end
end
