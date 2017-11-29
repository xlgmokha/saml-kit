module Saml
  module Kit
    class Response < Document
      class Builder
        attr_reader :user, :request
        attr_accessor :id, :reference_id, :now
        attr_accessor :version, :status_code
        attr_accessor :issuer, :sign, :destination, :encrypt

        def initialize(user, request)
          @user = user
          @request = request
          @id = SecureRandom.uuid
          @reference_id = SecureRandom.uuid
          @now = Time.now.utc
          @version = "2.0"
          @status_code = Namespaces::SUCCESS
          @issuer = configuration.issuer
          @destination = destination_for(request)
          @sign = want_assertions_signed
          @encrypt = false
        end

        def want_assertions_signed
          request.provider.want_assertions_signed
        rescue => error
          Saml::Kit.logger.error(error)
          true
        end

        def to_xml
          Signature.sign(sign: sign) do |xml, signature|
            xml.Response response_options do
              xml.Issuer(issuer, xmlns: Namespaces::ASSERTION)
              signature.template(id)
              xml.Status do
                xml.StatusCode Value: status_code
              end
              assertion(xml, signature)
            end
          end
        end

        def build
          Response.new(to_xml, request_id: request.id)
        end

        private

        def assertion(xml, signature)
          with_encryption(xml) do |xml|
            xml.Assertion(assertion_options) do
              xml.Issuer issuer
              signature.template(reference_id) unless encrypt
              xml.Subject do
                xml.NameID user.name_id_for(request.name_id_format), Format: request.name_id_format
                xml.SubjectConfirmation Method: Namespaces::BEARER do
                  xml.SubjectConfirmationData "", subject_confirmation_data_options
                end
              end
              xml.Conditions conditions_options do
                xml.AudienceRestriction do
                  xml.Audience request.issuer
                end
              end
              xml.AuthnStatement authn_statement_options do
                xml.AuthnContext do
                  xml.AuthnContextClassRef Namespaces::PASSWORD
                end
              end
              assertion_attributes = user.assertion_attributes_for(request)
              if assertion_attributes.any?
                xml.AttributeStatement do
                  assertion_attributes.each do |key, value|
                    xml.Attribute Name: key, NameFormat: Namespaces::URI, FriendlyName: key do
                      xml.AttributeValue value.to_s
                    end
                  end
                end
              end
            end
          end
        end

        def with_encryption(xml)
          if encrypt
            temp = ::Builder::XmlMarkup.new
            yield temp
            raw_xml_to_encrypt = temp.target!

            encryption_certificate = request.provider.encryption_certificates.first
            public_key = encryption_certificate.public_key

            cipher = OpenSSL::Cipher.new('AES-256-CBC')
            cipher.encrypt
            key = cipher.random_key
            iv = cipher.random_iv
            encrypted = cipher.update(raw_xml_to_encrypt) + cipher.final

            Saml::Kit.logger.debug ['+iv', iv].inspect
            Saml::Kit.logger.debug ['+key', key].inspect

            xml.EncryptedAssertion xmlns: Namespaces::ASSERTION do
              xml.EncryptedData xmlns: Namespaces::XMLENC do
                xml.EncryptionMethod Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
                xml.KeyInfo xmlns: Namespaces::XMLDSIG do
                  xml.EncryptedKey xmlns: Namespaces::XMLENC do
                    xml.EncryptionMethod Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
                    xml.CipherData do
                      xml.CipherValue Base64.encode64(public_key.public_encrypt(key))
                    end
                  end
                end
                xml.CipherData do
                  xml.CipherValue Base64.encode64(iv + encrypted)
                end
              end
            end
          else
            yield xml
          end
        end

        def destination_for(request)
          if request.signed? && request.trusted?
            request.acs_url || request.provider.assertion_consumer_service_for(binding: :http_post).try(:location)
          else
            request.provider.assertion_consumer_service_for(binding: :http_post).try(:location)
          end
        end

        def configuration
          Saml::Kit.configuration
        end

        def response_options
          {
            ID: id.present? ? "_#{id}" : nil,
            Version: version,
            IssueInstant: now.iso8601,
            Destination: destination,
            Consent: Namespaces::UNSPECIFIED,
            InResponseTo: request.id,
            xmlns: Namespaces::PROTOCOL,
          }
        end

        def assertion_options
          {
            ID: "_#{reference_id}",
            IssueInstant: now.iso8601,
            Version: "2.0",
            xmlns: Namespaces::ASSERTION,
          }
        end

        def subject_confirmation_data_options
          {
            InResponseTo: request.id,
            NotOnOrAfter: 3.hours.since(now).utc.iso8601,
            Recipient: request.acs_url,
          }
        end

        def conditions_options
          {
            NotBefore: now.utc.iso8601,
            NotOnOrAfter: Saml::Kit.configuration.session_timeout.from_now.utc.iso8601,
          }
        end

        def authn_statement_options
          {
            AuthnInstant: now.iso8601,
            SessionIndex: assertion_options[:ID],
            SessionNotOnOrAfter: 3.hours.since(now).utc.iso8601,
          }
        end
      end
    end
  end
end
