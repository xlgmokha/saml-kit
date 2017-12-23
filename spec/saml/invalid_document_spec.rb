RSpec.describe Saml::Kit::InvalidDocument do
  subject { described_class.new(xml) }
  let(:xml) { "<xml></xml>" }

  it 'is invalid' do
    expect(subject).to be_invalid
    expect(subject.errors[:base]).to be_present
  end
end

