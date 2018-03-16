# frozen_string_literal: true

module Saml
  module Kit
    module Bindings
      # This class is responsible for
      # serializing/deserializing SAML
      # documents using the HTTP Redirect
      # binding specification.
      # https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf
      # {include:file:spec/saml/kit/bindings/http_redirect_spec.rb}
      class HttpRedirect < Binding
        include Serializable

        def initialize(location:)
          super(binding: Saml::Kit::Bindings::HTTP_REDIRECT, location: location)
        end

        def serialize(builder, relay_state: nil)
          builder.embed_signature = false
          builder.destination = location
          document = builder.build
          url_builder = UrlBuilder.new(configuration: builder.configuration)
          [url_builder.build(document, relay_state: relay_state), {}]
        end

        def deserialize(params, configuration: Saml::Kit.configuration)
          parameters = normalize(params_to_hash(params))
          document = deserialize_document_from(parameters, configuration)
          ensure_valid_signature(parameters, document)
          document
        end

        private

        def deserialize_document_from(params, configuration)
          xml = inflate(decode(unescape(saml_param_from(params))))
          Saml::Kit::Document.to_saml_document(
            xml,
            configuration: configuration
          )
        end

        def ensure_valid_signature(params, document)
          signature = params[:Signature]
          algorithm = params[:SigAlg]
          provider = document.provider
          return if signature.blank? || algorithm.blank?
          return if provider.nil?

          return document.signature_verified! if provider.verify(
            algorithm_for(algorithm),
            decode(signature),
            canonicalize(params)
          )
          raise ArgumentError, 'Invalid Signature'
        end

        def canonicalize(params)
          %i[SAMLRequest SAMLResponse RelayState SigAlg].map do |key|
            value = params[key]
            value.present? ? "#{key}=#{value}" : nil
          end.compact.join('&')
        end

        def algorithm_for(algorithm)
          case algorithm =~ /(rsa-)?sha(.*?)$/i && Regexp.last_match(2).to_i
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

        def normalize(params)
          {
            SAMLRequest: params['SAMLRequest'] || params[:SAMLRequest],
            SAMLResponse: params['SAMLResponse'] || params[:SAMLResponse],
            RelayState: params['RelayState'] || params[:RelayState],
            Signature: params['Signature'] || params[:Signature],
            SigAlg: params['SigAlg'] || params[:SigAlg],
          }
        end

        def params_to_hash(value)
          return value unless value.is_a?(String)
          Hash[URI.parse(value).query.split('&').map { |xx| xx.split('=', 2) }]
        end
      end
    end
  end
end
