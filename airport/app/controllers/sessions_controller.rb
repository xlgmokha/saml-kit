class SessionsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:create]
  skip_before_action :authenticate!

  def new
    builder = Saml::Kit::AuthenticationRequest::Builder.new
    @relay_state = JSON.generate(redirect_to: '/')
    # HTTP Redirect
    # * URI
    # * SigAlg
    # * Signature
    # * RelayState
    redirect_binding = idp_metadata.single_sign_on_service_for(binding: :http_redirect)
    @redirect_uri, _ = redirect_binding.serialize(builder, relay_state: @relay_state)

    # HTTP POST
    # * URI
    # * SAMLRequest/SAMLResponse
    post_binding = idp_metadata.single_sign_on_service_for(binding: :post)
    @post_uri, @saml_params = post_binding.serialize(builder, relay_state: @relay_state)
  end

  def create
    saml_binding = binding_for(request)
    @saml_response = saml_binding.deserialize(params)
    return render :error, status: :forbidden if @saml_response.invalid?

    session[:user] = { id: @saml_response.name_id }.merge(@saml_response.attributes)
    redirect_to dashboard_path
  end

  def destroy
    if params['SAMLRequest'].present?
      redirect_to new_session_path
    else
      saml_binding = idp_metadata.single_logout_service_for(binding: :post)
      builder = Saml::Kit::LogoutRequest::Builder.new(current_user, sign: true)
      @url, @saml_params = saml_binding.serialize(builder)
      reset_session
      render layout: "spinner"
    end
  end

  private

  def idp_metadata
    Rails.configuration.x.idp_metadata
  end

  def binding_for(request)
    target_binding = request.post? ? :post : :http_redirect
    sp.single_logout_service_for(binding: target_binding)
  end

  def sp
    Sp.default(request)
  end
end
