class User
  attr_reader :id, :email

  def initialize(id:, email:)
    @id = id
    @email = email
  end

  def name_id_for(name_id_format)
    Saml::Kit::Namespaces::PERSISTENT == name_id_format ? id : email
  end

  def assertion_attributes_for(request)
    request.trusted? ? { access_token: SecureRandom.uuid } : {}
  end
end
