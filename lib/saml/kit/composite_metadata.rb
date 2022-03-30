# frozen_string_literal: true

module Saml
  module Kit
    # This class implements the Composite
    # design pattern to allow client
    # component to work with a metadata
    # that provides an IDPSSODescriptor
    # and SPSSODescriptor element.
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

      def organization
        find { |x| x.organization.present? }.try(:organization)
      end

      def organization_name
        organization.name
      end

      def organization_url
        organization.url
      end

      def services(type)
        xpath = map do |x|
          "//md:EntityDescriptor/md:#{x.name}/md:#{type}"
        end.join('|')
        search(xpath).map do |item|
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

      def method_missing(name, *args, **kwargs)
        if (target = find { |x| x.respond_to?(name) })
          target.public_send(name, *args, **kwargs)
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
