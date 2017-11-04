class User < ApplicationRecord
  has_secure_password
  after_initialize do
    self.uuid = SecureRandom.uuid unless self.uuid
  end

  def assertion_attributes_for(request)
    {
      id: uuid,
      email: email,
      created_at: created_at,
    }
  end

  def self.login(email, password)
    return if email.blank? || password.blank?

    user = User.find_by!(email: email)
    user.authenticate(password) ? user : nil
  rescue ActiveRecord::RecordNotFound
    nil
  end
end
