require 'rails_helper'

describe SessionsController do
  describe "#new" do
    let(:relay_state) { CGI.escape(JSON.generate(inbound_path: "/")) }
    let(:saml_request) { "blah" }
    let(:auth_host) { "https://auth.dev/auth" }

    it 'generates a saml request and redirects to the auth host' do
      travel_to 1.seconds.from_now
      allow(Saml::Kit::SamlRequest).to receive(:encode).and_return(saml_request)
      allow(Rails.configuration.x).to receive(:authentication_host).and_return(auth_host)

      get :new

      expect(response).to redirect_to(
        [
          auth_host,
          "/session/new?SAMLRequest=",
          saml_request,
          "&RelayState=",
          relay_state,
        ].join
      )
    end
  end

  describe "#create" do
    let(:saml_response) do
      Saml::Kit::SamlResponse::Builder.new(user, auth_request).build.encode
    end
    let(:auth_request) { double(id: '1', issuer: 'issuer', acs_url: '')  }
    let(:user) { double(uuid: user_id, assertion_attributes: { email: email, blah: 'blah' }) }
    let(:email) { FFaker::Internet.email }
    let(:user_id) { SecureRandom.uuid }

    it 'logs the correct user in' do
      post :create, params: { SAMLResponse: saml_response }

      expect(session[:email]).to eql(email)
      expect(session[:user_id]).to eql(user_id)
      expect(response).to redirect_to(dashboard_path)
    end
  end
end
