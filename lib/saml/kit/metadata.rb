# frozen_string_literal: true

module Saml
  module Kit
    # The Metadata object can be used to parse an XML string of metadata.
    #
    #   metadata = Saml::Kit::Metadata.from(raw_xml)
    #
    # It can also be used to generate a new metadata string.
    #
    #  metadata = Saml::Kit::Metadata.build do |builder|
    #    builder.entity_id = "my-issuer"
    #    builder.build_service_provider do |x|
    #      x.add_assertion_consumer_service(assertions_url, binding: :http_post)
    #      x.add_single_logout_service(logout_url, binding: :http_post)
    #    end
    #    builder.build_identity_provider do |x|
    #      x.add_single_sign_on_service(login_url, binding: :http_redirect)
    #      x.add_single_logout_service(logout_url, binding: :http_post)
    #    end
    #  end
    #  puts metadata.to_xml(pretty: true)
    #
    # See {Saml::Kit::Builders::ServiceProviderMetadata} and
    # {Saml::Kit::Builders::IdentityProviderMetadata}
    # for a list of options that can be specified.
    # {include:file:spec/examples/metadata_spec.rb}
    class Metadata
      include ActiveModel::Validations
      include Buildable
      include Translatable
      include XmlParseable
      include XsdValidatable

      validates_presence_of :metadata
      validate :must_contain_descriptor
      validate :must_match_xsd
      validate :must_have_valid_signature

      attr_reader :name

      def initialize(name, content)
        @name = name
        @content = content
      end

      # Returns the /EntityDescriptor/@entityID
      def entity_id
        at_xpath('/md:EntityDescriptor/@entityID').try(:value)
      end

      # Returns the supported NameIDFormats.
      def name_id_formats
        search("/md:EntityDescriptor/md:#{name}/md:NameIDFormat").map(&:text)
      end

      # Returns the Organization Name
      def organization_name
        xpath = '/md:EntityDescriptor/md:Organization/md:OrganizationName'
        at_xpath(xpath).try(:text)
      end

      # Returns the Organization URL
      def organization_url
        xpath = '/md:EntityDescriptor/md:Organization/md:OrganizationURL'
        at_xpath(xpath).try(:text)
      end

      # Returns the Company
      def contact_person_company
        at_xpath('/md:EntityDescriptor/md:ContactPerson/md:Company').try(:text)
      end

      # Returns each of the X509 certificates.
      def certificates(
        xpath = "/md:EntityDescriptor/md:#{name}/md:KeyDescriptor"
      )
        @certificates ||= search(xpath).map do |item|
          xpath = './ds:KeyInfo/ds:X509Data/ds:X509Certificate'
          namespaces = { 'ds' => ::Xml::Kit::Namespaces::XMLDSIG }
          cert = item.at_xpath(xpath, namespaces).try(:text)
          use_attribute = item.attribute('use')
          ::Xml::Kit::Certificate.new(cert, use: use_attribute.try(:value))
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
      # @param type [String] the type of service.
      # .E.g. `AssertionConsumerServiceURL`
      def services(type)
        search("/md:EntityDescriptor/md:#{name}/md:#{type}").map do |item|
          binding = item.attribute('Binding').value
          location = item.attribute('Location').value
          Saml::Kit::Bindings.create_for(binding, location)
        end
      end

      # Returns a specifing service binding.
      #
      # @param binding [Symbol] can be `:http_post` or `:http_redirect`.
      # @param type [Symbol] can be on the service element like
      # `AssertionConsumerServiceURL`, `SingleSignOnService` or
      # `SingleLogoutService`.
      def service_for(binding:, type:)
        binding = Saml::Kit::Bindings.binding_for(binding)
        services(type).find { |xxx| xxx.binding?(binding) }
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
      # @param user [Object] a user object that responds to `name_id_for` and
      # `assertion_attributes_for`.
      # @param binding [Symbol] can be `:http_post` or `:http_redirect`.
      # @param relay_state [String] the relay state to have echo'd back.
      # @return [Array] Returns an array with a url and Hash of parameters to
      # send to the other party.
      def logout_request_for(user, binding: :http_post, relay_state: nil)
        builder = Saml::Kit::LogoutRequest.builder(user) do |xxx|
          yield xxx if block_given?
        end
        request_binding = single_logout_service_for(binding: binding)
        request_binding.serialize(builder, relay_state: relay_state)
      end

      # Returns the certificate that matches the fingerprint
      #
      # @param fingerprint [Saml::Kit::Fingerprint] the fingerprint to search.
      # @param use [Symbol] the type of certificates to look at.
      # Can be `:signing` or `:encryption`.
      # @return [Xml::Kit::Certificate] returns the matching
      # `{Xml::Kit::Certificate}`
      def matches?(fingerprint, use: :signing)
        certificates.find do |xxx|
          xxx.for?(use) && xxx.fingerprint == fingerprint
        end
      end

      # Verifies the signature and data using the signing certificates.
      #
      # @param algorithm [OpenSSL::Digest] the digest algorithm to use.
      # E.g. `OpenSSL::Digest::SHA256`
      # @param signature [String] the signature to verify
      # @param data [String] the data that is used to produce the signature.
      # @return [Xml::Kit::Certificate] the certificate that was used to
      # produce the signature.
      def verify(algorithm, signature, data)
        signing_certificates.find do |certificate|
          certificate.public_key.verify(algorithm, signature, data)
        end
      end

      def signature(xpath = '/md:EntityDescriptor/ds:Signature')
        @signature ||= Signature.new(at_xpath(xpath))
      end

      class << self
        # Creates a `{Saml::Kit::Metadata}` object from a raw XML [String].
        #
        # @param content [String] the raw metadata XML.
        # @return [Saml::Kit::Metadata] the metadata document or subclass.
        def from(content)
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

        # @!visibility private
        def builder_class
          Saml::Kit::Builders::Metadata
        end
      end

      private

      attr_reader :content

      def metadata
        at_xpath("/md:EntityDescriptor/md:#{name}").present?
      end

      def must_contain_descriptor
        errors[:base] << error_message(:invalid) unless metadata
      end

      def must_match_xsd
        matches_xsd?(METADATA_XSD)
      end

      def must_have_valid_signature
        return unless signature.present?

        signature.valid?
        signature.errors.each do |attribute, error|
          errors[attribute] << error
        end
      end
    end
  end
end
