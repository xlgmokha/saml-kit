class User
  attr_reader :id, :email, :attributes

  def initialize(attributes)
    @id = attributes[:id]
    @email = attributes[:email]
    @attributes = attributes
  end

  def name_id_for(name_id_format)
    if Saml::Kit::Namespaces::PERSISTENT == name_id_format
      id
    else
      email
    end
  end
end
