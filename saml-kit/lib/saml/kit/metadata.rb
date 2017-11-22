module Saml
  module Kit
    class Metadata
      include ActiveModel::Validations
      include XsdValidatable

      METADATA_XSD = File.expand_path("./xsd/saml-schema-metadata-2.0.xsd", File.dirname(__FILE__)).freeze
      NAMESPACES = {
        "NameFormat": Namespaces::ATTR_SPLAT,
        "ds": Namespaces::XMLDSIG,
        "md": Namespaces::METADATA,
        "saml": Namespaces::ASSERTION,
      }.freeze

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
        find_by("/md:EntityDescriptor/@entityID").value
      end

      def name_id_formats
        find_all("/md:EntityDescriptor/md:#{name}/md:NameIDFormat").map(&:text)
      end

      def certificates
        @certificates ||= find_all("/md:EntityDescriptor/md:#{name}/md:KeyDescriptor").map do |item|
          cert = item.at_xpath("./ds:KeyInfo/ds:X509Data/ds:X509Certificate", NAMESPACES).text
          {
            text: cert,
            fingerprint: Fingerprint.new(cert).algorithm(hash_algorithm),
            use: item.attribute('use').value.to_sym,
          }
        end
      end

      def encryption_certificates
        certificates.find_all { |x| x[:use] == :encryption }
      end

      def signing_certificates
        certificates.find_all { |x| x[:use] == :signing }
      end

      def services(type)
        find_all("/md:EntityDescriptor/md:#{name}/md:#{type}").map do |item|
          binding = item.attribute("Binding").value
          location = item.attribute("Location").value
          binding_for(binding, location)
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

      def matches?(fingerprint, use: :signing)
        if :signing == use.to_sym
          hash_value = fingerprint.algorithm(hash_algorithm)
          signing_certificates.find do |signing_certificate|
            Saml::Kit.logger.debug [hash_value, signing_certificate[:fingerprint]].inspect
            hash_value == signing_certificate[:fingerprint]
          end
        end
      end

      def to_h
        @xml_hash ||= Hash.from_xml(to_xml)
      end

      def to_xml(pretty: false)
        pretty ? Nokogiri::XML(@xml).to_xml(indent: 2) : @xml
      end

      def to_s
        to_xml
      end

      def verify(algorithm, signature, data)
        signing_certificates.find do |cert|
          x509 = OpenSSL::X509::Certificate.new(Base64.decode64(cert[:text]))
          public_key = x509.public_key
          public_key.verify(algorithm, signature, data)
        end
      end

      def self.from(content)
        hash = Hash.from_xml(content)
        entity_descriptor = hash["EntityDescriptor"]
        if entity_descriptor.keys.include?("SPSSODescriptor")
          Saml::Kit::ServiceProviderMetadata.new(content)
        elsif entity_descriptor.keys.include?("IDPSSODescriptor")
          Saml::Kit::IdentityProviderMetadata.new(content)
        end
      end

      private

      def document
        @document ||= Nokogiri::XML(@xml)
      end

      def find_by(xpath)
        document.at_xpath(xpath, NAMESPACES)
      end

      def find_all(xpath)
        document.search(xpath, NAMESPACES)
      end

      def metadata
        find_by("/md:EntityDescriptor/md:#{name}").present?
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

      def binding_for(binding, location)
        Bindings.create_for(binding, location)
      end
    end
  end
end
