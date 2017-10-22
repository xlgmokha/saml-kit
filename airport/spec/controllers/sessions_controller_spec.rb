require 'rails_helper'

describe SessionsController do
  describe "#new" do
    let(:relay_state) { CGI.escape(JSON.generate(inbound_path: "/")) }
    let(:saml_request) { "blah" }
    let(:auth_host) { "https://auth.dev/auth" }

    it 'generates a saml request and redirects to the auth host' do
      travel_to 1.seconds.from_now
      allow(SamlRequest).to receive(:build).and_return(saml_request)
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
    let(:saml_response) { IO.read('spec/fixtures/encoded_response.txt') }
    let(:email) { 'mokha@cisco.com' }
    let(:bearer_token) { SecureRandom.uuid }
    let(:user_id) { '760a54e2-31ba-4dfa-9303-fa6887270980' }
    let(:username) { Rails.configuration.x.api_client_id }
    let(:password) { Rails.configuration.x.api_client_secret }

    it 'logs the correct user in' do
      expected_code = ActionController::HttpAuthentication::Basic.encode_credentials(username, password).split(' ', 2).second

      response_body = {
        "version":"v1.2.0",
        "metadata":{ "links":{ "self":"http://test.host/v1/users/#{user_id}/api_credentials" } },
        "data":{
          "access_token": bearer_token,
          "token_type":"Bearer",
          "expires_in":1799,
          "expires_at":"2017-10-03T19:38:26Z",
        }
      }
      stub_request(:post, "https://portal.dev/v1/users/#{user_id}/api_credentials").
        with(body: "{\"grant_type\":\"authorization_code\",\"code\":\"#{expected_code}\"}", headers: {'Accept'=>'application/json', 'Content-Type'=>'application/json'}).
        to_return(status: 201, body: response_body.to_json)

      post :create, params: { SAMLResponse: saml_response }

      expect(session[:email]).to eql(email)
      expect(session[:user_id]).to eql(user_id)
      expect(session[:access_token]).to eql(bearer_token)
      expect(response).to redirect_to(dashboard_path)
    end
  end
end
