module Saml
  module Kit
    class HttpRedirectBinding < Binding
      def serialize(builder, relay_state: nil)
        builder.sign = false
        builder.destination = location
        document = builder.build
        [UrlBuilder.new.build(document, relay_state: relay_state), {}]
      end

      def deserialize(params)
        document = deserialize_document_from!(params)
        ensure_valid_signature!(params, document)
        document
      end

      private

      def deserialize_document_from!(params)
        if params['SAMLRequest'].present?
          deserialize_request(CGI.unescape(params['SAMLRequest']))
        elsif params['SAMLResponse'].present?
          deserialize_response(CGI.unescape(params['SAMLResponse']))
        else
          raise ArgumentError.new("SAMLRequest or SAMLResponse parameter is required.")
        end
      end

      def ensure_valid_signature!(params, document)
        return if params['Signature'].blank? || params['SigAlg'].blank?

        signature = Base64.decode64(params['Signature'])
        canonical_form = ['SAMLRequest', 'SAMLResponse', 'RelayState', 'SigAlg'].map do |key|
          value = params[key]
          value.present? ? "#{key}=#{value}" : nil
        end.compact.join('&')

        valid = document.provider.verify(algorithm_for(params['SigAlg']), signature, canonical_form)
        raise ArgumentError.new("Invalid Signature") unless valid
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
