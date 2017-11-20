class SessionsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:new, :destroy]
  before_action :saml_request, only: [:new, :create, :destroy]
  rescue_from ActiveRecord::RecordInvalid do |error|
    render_error(:forbidden, model: error.record)
  end

  def new
    @raw_params = raw_params
    session[:request_binding] = request.post? ? :post : :http_redirect
  end

  def create
    if user = User.login(user_params[:email], user_params[:password])
      reset_session
      session[:user_id] = user.id
      response_binding = saml_request.provider.assertion_consumer_service_for(binding: :post)
      saml_response = saml_request.response_for(user)
      @url, @saml_params = response_binding.serialize(saml_response, relay_state: saml_params[:RelayState])
      render layout: "spinner"
    else
      @raw_params = raw_params
      flash[:error] = "Invalid Credentials"
      render :new
    end
  end

  def destroy
    if saml_params[:SAMLRequest].present?
      user = User.find_by(uuid: saml_request.name_id)
      response_binding = saml_request.provider.single_logout_service_for(binding: :post)
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

  def saml_request
    @saml_request ||= request_binding.deserialize(raw_params).tap do |saml_request|
      if saml_request.invalid?
        raise ActiveRecord::RecordInvalid.new(saml_request)
      end
    end
  end

  def idp
    Idp.default(request)
  end

  def request_binding
    target_binding = session[:request_binding]
    target_binding = target_binding || (request.post? ? :post : :http_redirect)
    idp.single_sign_on_service_for(binding: target_binding)
  end

  def raw_params
    if request.post?
      saml_params
    else
      Hash[request.query_string.split("&").map { |x| x.split("=", 2) }]
    end
  end
end
