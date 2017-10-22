class User < ApplicationRecord
  has_secure_password
  after_initialize do
    self.uuid = SecureRandom.uuid unless self.uuid
  end

  def assertion_attributes
    {
      id: uuid,
      email: email,
      created_at: created_at,
    }
  end
end
