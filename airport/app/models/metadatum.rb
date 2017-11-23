class Metadatum < ApplicationRecord
  def to_xml
    to_saml.to_xml
  end

  def to_saml
    Saml::Kit::Metadata.from(metadata)
  end
end
