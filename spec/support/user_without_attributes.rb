# frozen_string_literal: true

class UserWithoutAttributes
  attr_accessor :name_id

  def initialize(name_id: SecureRandom.uuid)
    @name_id = name_id
  end

  def name_id_for(_format)
    name_id
  end
end
