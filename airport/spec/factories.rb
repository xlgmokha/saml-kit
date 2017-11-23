FactoryGirl.define do
  factory :metadatum do
    entity_id FFaker::Internet.uri("https")
    metadata Saml::Kit::IdentityProviderMetadata::Builder.new.to_xml
  end
end
