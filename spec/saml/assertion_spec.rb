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
  end
end
