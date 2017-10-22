require 'builder'

class SamlResponse
  def initialize(xml)
    @xml = xml
  end

  def to_xml
    @xml
  end

  def self.for(user, authentication_request)
    builder = Builder.new(user, authentication_request)
    builder.build
  end

  class Builder
    attr_reader :user, :request, :id, :reference_id

    def initialize(user, request)
      @user = user
      @request = request
      @id = SecureRandom.uuid
      @reference_id = SecureRandom.uuid
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
        IssueInstant: Time.now.utc.iso8601,
        Destination: request.acs_url,
        Consent: Namespaces::Consents::UNSPECIFIED,
        InResponseTo: request.id,
        "xmlns:samlp" => Namespaces::PROTOCOL,
      }
    end

    def assertion_options
      {
        ID: "_#{reference_id}",
        IssueInstant: Time.now.utc.iso8601,
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

    def name_id_format
      "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    end
  end
end
