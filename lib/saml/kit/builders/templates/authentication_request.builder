xml.tag!('samlp:AuthnRequest', request_options) do
  xml.tag!('saml:Issuer', issuer)
  signature.template(id)
  xml.tag!('samlp:NameIDPolicy', Format: name_id_format)
end
