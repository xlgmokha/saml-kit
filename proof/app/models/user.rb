class User < ApplicationRecord
  has_secure_password
  after_initialize do
    self.uuid = SecureRandom.uuid unless self.uuid
  end

  def name_id_for(request)
    if Saml::Kit::Namespaces::PERSISTENT == request.name_id_format
      uuid
    else
      email
    end
  end

  def assertion_attributes_for(request)
    request.trusted? ? trusted_attributes : {}
  end

  def self.login(email, password)
    return if email.blank? || password.blank?

    user = User.find_by!(email: email)
    user.authenticate(password) ? user : nil
  rescue ActiveRecord::RecordNotFound
    nil
  end

  private

  def access_token
    BearerToken.new.encode(id: uuid)
  end

  def trusted_attributes
    {
      id: uuid,
      email: email,
      created_at: created_at,
      access_token: access_token,
    }
  end
end
