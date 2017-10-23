class User
  attr_reader :id, :email

  def initialize(attributes)
    @id = attributes[:id]
    @email = attributes[:email]
  end
end
