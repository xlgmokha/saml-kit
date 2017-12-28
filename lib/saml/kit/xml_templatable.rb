module Saml
  module Kit
    module XmlTemplatable
      include ::Xml::Kit::Templatable

      def template_path
        root_path = File.expand_path(File.dirname(__FILE__))
        template_name = "#{self.class.name.split("::").last.underscore}.builder"
        File.join(root_path, "builders/templates/", template_name)
      end

      # Returns true if an embedded signature is requested and at least one signing certificate is available via the configuration.
      def sign?
        return configuration.sign? if embed_signature.nil?
        embed_signature && configuration.sign?
      end

      # @deprecated Use {#embed_signature=} instead of this method.
      def sign=(value)
        Saml::Kit.deprecate("sign= is deprecated. Use embed_signature= instead.")
        self.embed_signature = value
      end

      def digest_method
        configuration.digest_method
      end

      def signature_method
        configuration.signature_method
      end

      def signing_key_pair
        configuration.key_pairs(use: :signing).last
      end
    end
  end
end
