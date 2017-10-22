FactoryGirl.define do
  sequence :saml_response do |n|
    xml = IO.read("spec/fixtures/signed_response.xml")
    xml.gsub!('2016-10-17T16:43:49.381Z', DateTime.now.iso8601)
    xml.gsub!('https://portal', 'http://test.host')
    xml
  end
end
