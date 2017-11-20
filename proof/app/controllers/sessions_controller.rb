class SessionsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:new, :destroy]
  before_action :load_saml_request, only: [:new, :create, :destroy]
  rescue_from ActiveRecord::RecordInvalid do |error|
    render_error(:forbidden, model: error.record)
  end

  def new
    session[:SAMLRequest] ||= params[:SAMLRequest]
    session[:RelayState] ||= params[:RelayState]
  end

  def create
    if user = User.login(user_params[:email], user_params[:password])
      reset_session
      session[:user_id] = user.id
      response_binding = @saml_request.provider.assertion_consumer_service_for(binding: :post)
      @url, @saml_params = response_binding.serialize(@saml_request.response_for(user), relay_state: session[:RelayState])
      render layout: "spinner"
    else
      redirect_to new_session_path, error: "Invalid Credentials"
    end
  end

  def destroy
    if params['SAMLRequest'].present?
      saml_request = load_saml_request
      user = User.find_by(uuid: saml_request.name_id)
      response_binding = saml_request.provider.single_logout_service_for(binding: :post)
      saml_response = saml_request.response_for(user)
      @url, @saml_params = response_binding.serialize(saml_response, relay_state: params[:RelayState])
      reset_session
      render layout: "spinner"
    elsif params['SAMLResponse'].present?
    else
    end
  end

  private

  def user_params
    params.require(:user).permit(:email, :password)
  end

  def load_saml_request
    @saml_request = request_binding_for(request).deserialize(raw_params_for(request))
    raise ActiveRecord::RecordInvalid.new(@saml_request) if @saml_request.invalid?
    @saml_request
  end

  def idp
    Idp.default(request)
  end

  def request_binding_for(request)
    target_binding = request.post? ? :post : :http_redirect
    idp.single_sign_on_service_for(binding: target_binding)
  end

  def raw_params_for(request)
    if request.post?
      request.params
    else
      Hash[request.query_string.split("&").map { |x| x.split("=", 2) }]
    end
  end
end
