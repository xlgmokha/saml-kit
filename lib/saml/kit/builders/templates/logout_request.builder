# frozen_string_literal: true

xml.instruct!
xml.LogoutRequest logout_request_options do
  xml.Issuer({ xmlns: Saml::Kit::Namespaces::ASSERTION }, issuer)
  signature_for(reference_id: id, xml: xml)
  xml.NameID name_id_options, user.name_id_for(name_id_format)
end
