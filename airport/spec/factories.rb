FactoryGirl.define do
  factory :metadatum do
    entity_id FFaker::Internet.uri("https")
    metadata Saml::Kit::IdentityProvider::Builder.new.to_xml
  end
end
