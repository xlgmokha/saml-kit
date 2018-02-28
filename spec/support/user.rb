# frozen_string_literal: true

class User
  attr_accessor :name_id, :attributes

  def initialize(name_id: SecureRandom.uuid, attributes: {})
    @name_id = name_id
    @attributes = attributes
  end

  def name_id_for(_format)
    name_id
  end

  def assertion_attributes_for(_request)
    attributes
  end
end
