class User < ApplicationRecord
  has_secure_password
  after_initialize do
    self.uuid = SecureRandom.uuid unless self.uuid
  end
end
