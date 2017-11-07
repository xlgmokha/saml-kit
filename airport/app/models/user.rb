class User
  attr_reader :id, :email, :attributes

  def initialize(attributes)
    @id = attributes[:id]
    @email = attributes[:email]
    @attributes = attributes
  end
end
