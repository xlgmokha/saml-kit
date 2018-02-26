# frozen_string_literal: true

RSpec.describe Saml::Kit::InvalidDocument do
  it 'is invalid' do
    subject = described_class.new('<xml></xml>')
    expect(subject).to be_invalid
    expect(subject.errors[:base]).to be_present
  end

  it 'is invalid with something that not xml' do
    subject = described_class.new('NOT XML')
    expect(subject).to be_invalid
    expect(subject.errors[:base]).to be_present
  end
end
