module Saml
  module Kit
    class Metadata
      include ActiveModel::Validations
      include XsdValidatable
      include Buildable
      METADATA_XSD = File.expand_path("./xsd/saml-schema-metadata-2.0.xsd", File.dirname(__FILE__)).freeze

      validates_presence_of :metadata
      validate :must_contain_descriptor
      validate :must_match_xsd
      validate :must_have_valid_signature

      attr_reader :xml, :name
      attr_accessor :hash_algorithm

      def initialize(name, xml)
        @name = name
        @xml = xml
        @hash_algorithm = OpenSSL::Digest::SHA256
      end

      def entity_id
        document.find_by("/md:EntityDescriptor/@entityID").value
      end

      def name_id_formats
        document.find_all("/md:EntityDescriptor/md:#{name}/md:NameIDFormat").map(&:text)
      end

      def certificates
        @certificates ||= document.find_all("/md:EntityDescriptor/md:#{name}/md:KeyDescriptor").map do |item|
          cert = item.at_xpath("./ds:KeyInfo/ds:X509Data/ds:X509Certificate", Xml::NAMESPACES).text
          Certificate.new(cert, use: item.attribute('use').value.to_sym)
        end
      end

      def encryption_certificates
        certificates.find_all(&:encryption?)
      end

      def signing_certificates
        certificates.find_all(&:signing?)
      end

      def services(type)
        document.find_all("/md:EntityDescriptor/md:#{name}/md:#{type}").map do |item|
          binding = item.attribute("Binding").value
          location = item.attribute("Location").value
          Saml::Kit::Bindings.create_for(binding, location)
        end
      end

      def service_for(binding:, type:)
        binding = Saml::Kit::Bindings.binding_for(binding)
        services(type).find { |x| x.binding?(binding) }
      end

      def single_logout_services
        services('SingleLogoutService')
      end

      def single_logout_service_for(binding:)
        service_for(binding: binding, type: 'SingleLogoutService')
      end

      def logout_request_for(user, binding: :http_post, relay_state: nil)
        builder = Saml::Kit::LogoutRequest.builder(user) do |x|
          yield x if block_given?
        end
        request_binding = single_logout_service_for(binding: binding)
        request_binding.serialize(builder, relay_state: relay_state)
      end

      def matches?(fingerprint, use: :signing)
        certificates.find do |certificate|
          certificate.for?(use) && certificate.fingerprint == fingerprint
        end
      end

      def to_h
        @xml_hash ||= Hash.from_xml(to_xml)
      end

      def to_xml(pretty: false)
        document.to_xml(pretty: pretty)
      end

      def to_s
        to_xml
      end

      def verify(algorithm, signature, data)
        signing_certificates.find do |cert|
          cert.public_key.verify(algorithm, signature, data)
        end
      end

      def self.from(content)
        hash = Hash.from_xml(content)
        entity_descriptor = hash["EntityDescriptor"]
        if entity_descriptor.key?("SPSSODescriptor") && entity_descriptor.key?("IDPSSODescriptor")
          Saml::Kit::CompositeMetadata.new(content)
        elsif entity_descriptor.keys.include?("SPSSODescriptor")
          Saml::Kit::ServiceProviderMetadata.new(content)
        elsif entity_descriptor.keys.include?("IDPSSODescriptor")
          Saml::Kit::IdentityProviderMetadata.new(content)
        end
      end

      private

      def document
        @document ||= Xml.new(xml)
      end

      def metadata
        document.find_by("/md:EntityDescriptor/md:#{name}").present?
      end

      def must_contain_descriptor
        errors[:base] << error_message(:invalid) unless metadata
      end

      def must_match_xsd
        matches_xsd?(METADATA_XSD)
      end

      def must_have_valid_signature
        return if to_xml.blank?

        unless valid_signature?
          errors[:base] << error_message(:invalid_signature)
        end
      end

      def valid_signature?
        xml = Saml::Kit::Xml.new(to_xml)
        result = xml.valid?
        xml.errors.each do |error|
          errors[:base] << error
        end
        result
      end
    end
  end
end
