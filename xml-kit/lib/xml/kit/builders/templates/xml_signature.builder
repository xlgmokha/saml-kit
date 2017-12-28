xml.Signature "xmlns" => ::Xml::Kit::Namespaces::XMLDSIG do
  xml.SignedInfo do
    xml.CanonicalizationMethod Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"
    xml.SignatureMethod Algorithm: signature_method
    xml.Reference URI: "##{reference_id}" do
      xml.Transforms do
        xml.Transform Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
        xml.Transform Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"
      end
      xml.DigestMethod Algorithm: digest_method
      xml.DigestValue ""
    end
  end
  xml.SignatureValue ""
  xml.KeyInfo do
    xml.X509Data do
      xml.X509Certificate certificate.stripped
    end
  end
end
