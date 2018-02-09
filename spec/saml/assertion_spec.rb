RSpec.describe Saml::Kit::Assertion do
  describe "#active?" do
    let(:configuration) do
      Saml::Kit::Configuration.new do |config|
        config.session_timeout = 30.minutes
        config.clock_drift = 30.seconds
      end
    end

    it 'is valid after a valid session window + drift' do
      now = Time.current
      travel_to now
      xml_hash = {
        'Response' => {
          'Assertion' => {
            'Conditions' => {
              'NotBefore' => now.utc.iso8601,
              'NotOnOrAfter' => configuration.session_timeout.since(now).iso8601,
            }
          }
        }
      }
      subject = described_class.new(xml_hash, configuration: configuration)
      travel_to (configuration.clock_drift - 1.second).before(now)
      expect(subject).to be_active
      expect(subject).to_not be_expired
    end

    it 'interprets integers correctly' do
      configuration.clock_drift = 30
      now = Time.current
      travel_to now
      xml_hash = {
        'Response' => {
          'Assertion' => {
            'Conditions' => {
              'NotBefore' => now.utc.iso8601,
              'NotOnOrAfter' => configuration.session_timeout.since(now).iso8601,
            }
          }
        }
      }

      subject = described_class.new(xml_hash, configuration: configuration)
      expect(subject).to be_active
      expect(subject).to_not be_expired
    end
  end

  describe "#present?" do
    it 'returns false when the assertion is empty' do
      xml_hash = { 'Response' => { } }
      subject = described_class.new(xml_hash)
      expect(subject).to_not be_present
    end

    it 'returns true when the assertion is present' do
      xml_hash = { 'Response' => { 'Assertion' => { 'Conditions' => { } } } }
      subject = described_class.new(xml_hash)
      expect(subject).to be_present
    end
  end
end
