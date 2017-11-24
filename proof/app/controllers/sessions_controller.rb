class SessionsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:new, :destroy]

  def new
    target_binding = request.post? ? :http_post : :http_redirect
    binding = idp.single_sign_on_service_for(binding: target_binding)
    saml_request = binding.deserialize(raw_params)
    return render_error(:forbidden, model: saml_request) if saml_request.invalid?
    return post_back(saml_request, current_user) if current_user?

    session[:saml] = { params: raw_params.to_h, binding: target_binding }
  end

  def create
    if user = User.login(user_params[:email], user_params[:password])
      binding = idp.single_sign_on_service_for(binding: session[:saml][:binding])
      saml_request = binding.deserialize(session[:saml][:params])
      return render_error(:forbidden, model: saml_request) if saml_request.invalid?

      post_back(saml_request, user)
    else
      flash[:error] = "Invalid Credentials"
      render :new
    end
  end

  def destroy
    if saml_params[:SAMLRequest].present?
      binding = idp.single_logout_service_for(binding: :http_post)
      saml_request = binding.deserialize(raw_params).tap do |saml|
        raise ActiveRecord::RecordInvalid.new(saml) if saml.invalid?
      end
      user = User.find_by(uuid: saml_request.name_id)
      response_binding = saml_request.provider.single_logout_service_for(binding: :http_post)
      saml_response = saml_request.response_for(user)
      @url, @saml_params = response_binding.serialize(saml_response, relay_state: saml_params[:RelayState])
      reset_session
      render layout: "spinner"
    elsif saml_params[:SAMLResponse].present?
    else
    end
  end

  private

  def user_params
    params.require(:user).permit(:email, :password)
  end

  def saml_params
    params.permit(:SAMLRequest, :SAMLResponse, :SAMLEncoding, :SigAlg, :Signature)
  end

  def idp
    Idp.default(request)
  end

  def raw_params
    if request.post?
      saml_params
    else
      Hash[request.query_string.split("&").map { |x| x.split("=", 2) }]
    end
  end

  def post_back(saml_request, user)
    response_binding = saml_request.provider.assertion_consumer_service_for(binding: :http_post)
    saml_response = saml_request.response_for(user)
    @url, @saml_params = response_binding.serialize(saml_response, relay_state: saml_params[:RelayState])
    reset_session
    session[:user_id] = user.id
    render :create, layout: "spinner"
  end
end
