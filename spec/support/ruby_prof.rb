# frozen_string_literal: true

require 'ruby-prof'

module RubyProfiler
  def with_profiler
    result = RubyProf.profile do
      yield
    end
    printer = RubyProf::CallTreePrinter.new(result)
    printer.print(path: "tmp/profile/", profile: Time.now.utc.iso8601)
  end
end

RSpec.configure do |config|
  config.include RubyProfiler
end
