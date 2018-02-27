# frozen_string_literal: true

module Saml
  module Kit
    module XmlTemplatable
      TEMPLATES_DIR=Pathname.new(File.join(__dir__, 'builders/templates/'))
      include ::Xml::Kit::Templatable

      def template_path
        @template_path ||= TEMPLATES_DIR.join(template_name)
      end

      def template_name
        "#{self.class.name.split('::').last.underscore}.builder"
      end

      # Returns true if an embedded signature is requested and at least one signing certificate is available via the configuration.
      def sign?
        return configuration.sign? if embed_signature.nil?
        (embed_signature && configuration.sign?) ||
          (embed_signature && signing_key_pair.present?)
      end

      def encrypt_with(key_pair)
        self.encrypt = true
        self.encryption_certificate = key_pair.certificate
      end

      def digest_method
        configuration.digest_method
      end

      def signature_method
        configuration.signature_method
      end

      def signing_key_pair
        @signing_key_pair || configuration.key_pairs(use: :signing).last
      end
    end
  end
end
