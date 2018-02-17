module Saml
  module Kit
    class CompositeMetadata < Metadata # :nodoc:
      include Enumerable
      attr_reader :service_provider, :identity_provider

      def initialize(xml)
        super('IDPSSODescriptor', xml)
        @metadatum = [
          Saml::Kit::ServiceProviderMetadata.new(xml),
          Saml::Kit::IdentityProviderMetadata.new(xml),
        ]
      end

      def services(type)
        xpath = map { |x| "//md:EntityDescriptor/md:#{x.name}/md:#{type}" }.join('|')
        document.find_all(xpath).map do |item|
          binding = item.attribute('Binding').value
          location = item.attribute('Location').value
          Saml::Kit::Bindings.create_for(binding, location)
        end
      end

      def certificates
        flat_map(&:certificates)
      end

      def each(&block)
        @metadatum.each(&block)
      end

      def method_missing(name, *args)
        if (target = find { |x| x.respond_to?(name) })
          target.public_send(name, *args)
        else
          super
        end
      end

      def respond_to_missing?(method, *)
        find { |x| x.respond_to?(method) }
      end
    end
  end
end
