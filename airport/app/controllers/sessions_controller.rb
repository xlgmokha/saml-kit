class SessionsController < ApplicationController
  def new
    @metadatum = Metadatum.all
  end

  def create
    @saml_builder = builder_for(:login)
    if :http_redirect == params[:binding].to_sym
      redirect_binding = idp.single_sign_on_service_for(binding: :http_redirect)
      @redirect_uri, _ = redirect_binding.serialize(@saml_builder, relay_state: relay_state)
    else
      post_binding = idp.single_sign_on_service_for(binding: :http_post)
      @post_uri, @saml_params = post_binding.serialize(@saml_builder, relay_state: relay_state)
    end
  end

  def destroy
    binding = :http_redirect == params[:binding].to_sym ? :http_redirect : :http_post
    saml_binding = idp.single_logout_service_for(binding: binding)
    @url, @saml_params = saml_binding.serialize(builder_for(:logout))
  end

  private

  def idp(entity_id = params[:entity_id])
    Saml::Kit.configuration.registry.metadata_for(params[:entity_id])
  end

  def relay_state
    JSON.generate(redirect_to: '/')
  end

  def builder_for(type, entity_id: nil)
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
