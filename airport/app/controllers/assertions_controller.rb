class AssertionsController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:create, :destroy]

  def create
    saml_binding = sp.assertion_consumer_service_for(binding: :http_post)
    @saml_response = saml_binding.deserialize(params)
    logger.debug(@saml_response.to_xml(pretty: true))
    return render :error, status: :forbidden if @saml_response.invalid?

    session[@saml_response.issuer] = { id: @saml_response.name_id }.merge(@saml_response.attributes)
  end

  def destroy
    if params['SAMLRequest'].present?
      # IDP initiated logout
    elsif params['SAMLResponse'].present?
      saml_binding = sp.single_logout_service_for(binding: :http_post)
      @saml_response = saml_binding.deserialize(params)
      raise ActiveRecordRecordInvalid.new(@saml_response) if @saml_response.invalid?
      session[@saml_response.issuer] = nil
    end
  end

  private

  def sp
    Sp.default(request)
  end
end
