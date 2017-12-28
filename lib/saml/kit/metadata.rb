module Saml
  module Kit
    # The Metadata object can be used to parse an XML string of metadata.
    #
    #   metadata = Saml::Kit::Metadata.from(raw_xml)
    #
    # It can also be used to generate a new metadata string.
    #
    #   metadata = Saml::Kit::Metadata.build do |builder|
    #     builder.entity_id = "my-issuer"
    #     builder.build_service_provider do |x|
    #       x.add_assertion_consumer_service(assertions_url, binding: :http_post)
    #       x.add_single_logout_service(logout_url, binding: :http_post)
    #     end
    #     builder.build_identity_provider do |x|
    #       x.add_single_sign_on_service(login_url, binding: :http_redirect)
    #       x.add_single_logout_service(logout_url, binding: :http_post)
    #     end
    #   end
    #   puts metadata.to_xml(pretty: true)
    #
    # See {Saml::Kit::Builders::ServiceProviderMetadata} and {Saml::Kit::Builders::IdentityProviderMetadata}
    # for a list of options that can be specified.
    # {include:file:spec/examples/metadata_spec.rb}
    class Metadata
      METADATA_XSD = File.expand_path("./xsd/saml-schema-metadata-2.0.xsd", File.dirname(__FILE__)).freeze
      NAMESPACES = {
        "NameFormat": Namespaces::ATTR_SPLAT,
        "ds": ::Xml::Kit::Namespaces::XMLDSIG,
        "md": Namespaces::METADATA,
        "saml": Namespaces::ASSERTION,
        "samlp": Namespaces::PROTOCOL,
      }.freeze
      include ActiveModel::Validations
      include XsdValidatable
      include Translatable
      include Buildable

      validates_presence_of :metadata
      validate :must_contain_descriptor
      validate :must_match_xsd
      validate :must_have_valid_signature

      attr_reader :name

      def initialize(name, xml)
        @name = name
        @xml = xml
      end

      # Returns the /EntityDescriptor/@entityID
      def entity_id
        document.find_by("/md:EntityDescriptor/@entityID").value
      end

      # Returns the supported NameIDFormats.
      def name_id_formats
        document.find_all("/md:EntityDescriptor/md:#{name}/md:NameIDFormat").map(&:text)
      end

      # Returns the Organization Name
      def organization_name
        document.find_by("/md:EntityDescriptor/md:Organization/md:OrganizationName").try(:text)
      end

      # Returns the Organization URL
      def organization_url
        document.find_by("/md:EntityDescriptor/md:Organization/md:OrganizationURL").try(:text)
      end

      # Returns the Company
      def contact_person_company
        document.find_by("/md:EntityDescriptor/md:ContactPerson/md:Company").try(:text)
      end

      # Returns each of the X509 certificates.
      def certificates
        @certificates ||= document.find_all("/md:EntityDescriptor/md:#{name}/md:KeyDescriptor").map do |item|
          cert = item.at_xpath("./ds:KeyInfo/ds:X509Data/ds:X509Certificate", NAMESPACES).text
          ::Xml::Kit::Certificate.new(cert, use: item.attribute('use').value.to_sym)
        end
      end

      # Returns the encryption certificates
      def encryption_certificates
        certificates.find_all(&:encryption?)
      end

      # Returns the signing certificates.
      def signing_certificates
        certificates.find_all(&:signing?)
      end

      # Returns each of the service endpoints supported by this metadata.
      #
      # @param type [String] the type of service. .E.g. `AssertionConsumerServiceURL`
      def services(type)
        document.find_all("/md:EntityDescriptor/md:#{name}/md:#{type}").map do |item|
          binding = item.attribute("Binding").value
          location = item.attribute("Location").value
          Saml::Kit::Bindings.create_for(binding, location)
        end
      end

      # Returns a specifing service binding.
      #
      # @param binding [Symbol] can be `:http_post` or `:http_redirect`.
      # @param type [Symbol] can be on the service element like `AssertionConsumerServiceURL`, `SingleSignOnService` or `SingleLogoutService`.
      def service_for(binding:, type:)
        binding = Saml::Kit::Bindings.binding_for(binding)
        services(type).find { |x| x.binding?(binding) }
      end

      # Returns each of the SingleLogoutService bindings
      def single_logout_services
        services('SingleLogoutService')
      end

      # Returns the SingleLogoutService that matches the specified binding.
      #
      # @param binding [Symbol] can be `:http_post` or `:http_redirect`.
      def single_logout_service_for(binding:)
        service_for(binding: binding, type: 'SingleLogoutService')
      end

      # Creates a serialized LogoutRequest.
      #
      # @param user [Object] a user object that responds to `name_id_for` and `assertion_attributes_for`.
      # @param binding [Symbol] can be `:http_post` or `:http_redirect`.
      # @param relay_state [String] the relay state to have echo'd back.
      # @return [Array] Returns an array with a url and Hash of parameters to send to the other party.
      def logout_request_for(user, binding: :http_post, relay_state: nil)
        builder = Saml::Kit::LogoutRequest.builder(user) do |x|
          yield x if block_given?
        end
        request_binding = single_logout_service_for(binding: binding)
        request_binding.serialize(builder, relay_state: relay_state)
      end

      # Returns the certificate that matches the fingerprint
      #
      # @param fingerprint [Saml::Kit::Fingerprint] the fingerprint to search for.
      # @param use [Symbol] the type of certificates to look at. Can be `:signing` or `:encryption`.
      # @return [Xml::Kit::Certificate] returns the matching `{Xml::Kit::Certificate}`
      def matches?(fingerprint, use: :signing)
        certificates.find do |certificate|
          certificate.for?(use) && certificate.fingerprint == fingerprint
        end
      end

      # Returns the XML document converted to a Hash.
      def to_h
        @xml_hash ||= Hash.from_xml(to_xml)
      end

      # Returns the XML document as a String.
      #
      # @param pretty [Symbol] true to return a human friendly version of the XML.
      def to_xml(pretty: false)
        document.to_xml(pretty: pretty)
      end

      # Returns the XML document as a [String].
      def to_s
        to_xml
      end

      # Verifies the signature and data using the signing certificates.
      #
      # @param algorithm [OpenSSL::Digest] the digest algorithm to use. E.g. `OpenSSL::Digest::SHA256`
      # @param signature [String] the signature to verify
      # @param data [String] the data that is used to produce the signature.
      # @return [Xml::Kit::Certificate] the certificate that was used to produce the signature.
      def verify(algorithm, signature, data)
        signing_certificates.find do |certificate|
          certificate.public_key.verify(algorithm, signature, data)
        end
      end

      # Creates a `{Saml::Kit::Metadata}` object from a raw XML [String].
      #
      # @param content [String] the raw metadata XML.
      # @return [Saml::Kit::Metadata] the metadata document or subclass.
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

      # @!visibility private
      def self.builder_class
        Saml::Kit::Builders::Metadata
      end

      private

      attr_reader :xml

      def document
        @document ||= ::Xml::Kit::Document.new(xml, namespaces: NAMESPACES)
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
        xml = document
        result = xml.valid?
        xml.errors.each do |error|
          errors[:base] << error
        end
        result
      end
    end
  end
end
