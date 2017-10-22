require 'builder'

class SamlResponse
  def initialize(xml)
    @xml = xml
  end

  def acs_url
    Hash.from_xml(@xml)['Response']['Destination']
  end

  def to_xml
    @xml
  end

  def encode
    Base64.strict_encode64(to_xml)
  end

  class Builder
    attr_reader :user, :request, :id, :reference_id, :now

    def initialize(user, request)
      @user = user
      @request = request
      @id = SecureRandom.uuid
      @reference_id = SecureRandom.uuid
      @now = Time.now.utc
    end

    def to_xml
      xml = ::Builder::XmlMarkup.new
      xml.tag!("samlp:Response", response_options) do
        xml.Issuer(configuration.issuer, xmlns: Namespaces::ASSERTION)
        xml.tag!("samlp:Status") do
          xml.tag!('samlp:StatusCode', Value: Namespaces::Statuses::SUCCESS)
        end
        xml.Assertion(assertion_options) do
          xml.Issuer configuration.issuer
          xml.Subject do
            xml.NameID user.uuid, Format: name_id_format
            xml.SubjectConfirmation Method: Namespaces::Methods::BEARER do
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
              xml.AuthnContextClassRef Namespaces::AuthnContext::ClassRef::PASSWORD
            end
          end
          xml.AttributeStatement do
            user.assertion_attributes.each do |key, value|
              xml.Attribute Name: key, NameFormat: Namespaces::Formats::Attr::URI, FriendlyName: key do
                xml.AttributeValue value.to_s
              end
            end
          end
        end
      end
      xml.target!
    end

    def build
      SamlResponse.new(to_xml)
    end

    private

    def configuration
      Rails.configuration.x
    end

    def response_options
      {
        ID: "_#{id}",
        Version: "2.0",
        IssueInstant: now.iso8601,
        Destination: request.acs_url,
        Consent: Namespaces::Consents::UNSPECIFIED,
        InResponseTo: request.id,
        "xmlns:samlp" => Namespaces::PROTOCOL,
      }
    end

    def assertion_options
      {
        ID: "_#{reference_id}",
        IssueInstant: now.iso8601,
        Version: "2.0",
      }
    end

    def subject_confirmation_data_options
      {
        InResponseTo: request.id,
        NotOnOrAfter: 3.hours.from_now.utc.iso8601,
        Recipient: request.acs_url,
      }
    end

    def conditions_options
      {
        NotBefore: 5.seconds.ago.utc.iso8601,
        NotOnOrAfter: 3.hours.from_now.utc.iso8601,
      }
    end

    def authn_statement_options
      {
        AuthnInstant: now.iso8601,
        SessionIndex: assertion_options[:ID],
        SessionNotOnOrAfter: 3.hours.from_now.utc.iso8601,
      }
    end

    def name_id_format
      "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    end
  end
end
