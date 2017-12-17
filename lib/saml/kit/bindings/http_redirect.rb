module Saml
  module Kit
    module Bindings
      class HttpRedirect < Binding
        include Serializable

        def initialize(location:)
          super(binding: Saml::Kit::Bindings::HTTP_REDIRECT, location: location)
        end

        def serialize(builder, relay_state: nil)
          builder.embed_signature = false
          builder.destination = location
          document = builder.build
          [UrlBuilder.new(configuration: builder.configuration).build(document, relay_state: relay_state), {}]
        end

        def deserialize(params, configuration: Saml::Kit.configuration)
          document = deserialize_document_from!(params, configuration)
          ensure_valid_signature!(params, document)
          document
        end

        private

        def deserialize_document_from!(params, configuration)
          xml = inflate(decode(unescape(saml_param_from(params))))
          Saml::Kit.logger.debug(xml)
          Saml::Kit::Document.to_saml_document(xml, configuration: configuration)
        end

        def ensure_valid_signature!(params, document)
          return if params['Signature'].blank? || params['SigAlg'].blank?

          signature = decode(params['Signature'])
          canonical_form = ['SAMLRequest', 'SAMLResponse', 'RelayState', 'SigAlg'].map do |key|
            value = params[key]
            value.present? ? "#{key}=#{value}" : nil
          end.compact.join('&')

          return if document.provider.nil?
          if document.provider.verify(algorithm_for(params['SigAlg']), signature, canonical_form)
            document.signature_verified!
          else
            raise ArgumentError.new("Invalid Signature")
          end
        end

        def algorithm_for(algorithm)
          case algorithm =~ /(rsa-)?sha(.*?)$/i && $2.to_i
          when 256
            OpenSSL::Digest::SHA256.new
          when 384
            OpenSSL::Digest::SHA384.new
          when 512
            OpenSSL::Digest::SHA512.new
          else
            OpenSSL::Digest::SHA1.new
          end
        end
      end
    end
  end
end
