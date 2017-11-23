class Metadatum < ApplicationRecord
  def to_saml
    Saml::Kit::Metadata.from(metadata)
  end
end
