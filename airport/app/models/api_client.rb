class ApiClient
  attr_reader :session

  def initialize(session)
    @session = session
  end

  def user_id
    session[:user_id]
  end

  def access_token
    return session[:access_token] if session[:access_token].present?

    url = "https://portal.dev/v1/users/#{user_id}/api_credentials"
    payload = { grant_type: "authorization_code", code: authorization_code }
    result = RestClient::Resource.new(url, verify_ssl: OpenSSL::SSL::VERIFY_NONE).post(payload.to_json, { content_type: :json, accept: :json })
    json = JSON.parse(result.body, symbolize_names: true)
    json[:data][:access_token]
  end

  def computers
    url = "https://portal.dev/v1/computers/"
    result = RestClient::Resource.new(url, verify_ssl: OpenSSL::SSL::VERIFY_NONE).get(content_type: :json, accept: :json, authorization: "Bearer #{access_token}")
    JSON.parse(result.body, symbolize_names: true)[:data]
  end

  private

  def authorization_code(username: Rails.configuration.x.api_client_id, password: Rails.configuration.x.api_client_secret)
    ActionController::HttpAuthentication::Basic.encode_credentials(username, password).split(' ', 2).second
  end
end
