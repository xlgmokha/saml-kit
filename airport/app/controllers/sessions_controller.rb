class SessionsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:create]

  def new
    uri = URI.parse(Rails.configuration.x.authentication_host)
    uri.path += "/session/new"
    redirect_to uri.to_s + '?' + query_params
  end

  def create
    saml_response = SamlResponse.parse(params[:SAMLResponse])
    session[:user_id] = saml_response.name_id
    session[:email] = saml_response[:email]
    redirect_to dashboard_path
  end

  private

  def query_params
    {
      'SAMLRequest' => SamlRequest.build(AuthenticationRequest.new),
      'RelayState' => JSON.generate(inbound_path: '/'),
    }.map do |(x, y)|
      "#{x}=#{CGI.escape(y)}"
    end.join('&')
  end
end
