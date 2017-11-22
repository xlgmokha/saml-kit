class SessionsController < ApplicationController
  skip_before_action :authenticate!, only: [:new]

  def new
    # HTTP Redirect
    # * URI
    # * SigAlg
    # * Signature
    # * RelayState
    redirect_binding = idp.single_sign_on_service_for(binding: :http_redirect)
    @redirect_uri, _ = redirect_binding.serialize(builder_for(:login), relay_state: relay_state)
    # HTTP POST
    # * URI
    # * SAMLRequest/SAMLResponse
    post_binding = idp.single_sign_on_service_for(binding: :http_post)
    @post_uri, @saml_params = post_binding.serialize(builder_for(:login), relay_state: relay_state)
  end

  def destroy
    saml_binding = idp.single_logout_service_for(binding: :http_post)
    @url, @saml_params = saml_binding.serialize(builder_for(:logout))
    render layout: "spinner"
  end

  private

  def idp
    Rails.configuration.x.idp_metadata
  end

  def relay_state
    JSON.generate(redirect_to: '/')
  end

  def builder_for(type)
    case type
    when :login
      builder = Saml::Kit::AuthenticationRequest::Builder.new
      builder.acs_url = Sp.default(request).assertion_consumer_service_for(binding: :http_post).location
      builder
    when :logout
      Saml::Kit::LogoutRequest::Builder.new(current_user)
    end
  end
end
