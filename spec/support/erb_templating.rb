# frozen_string_literal: true

module ErbTemplating
  class Template
    def initialize(template_name, data)
      @erb = ERB.new(IO.read(File.join('spec/fixtures', "#{template_name}.erb")))
      @data = data
    end

    def fetch(key, default)
      @data.fetch(key, default)
    end

    def __expand
      @erb.result(binding)
    end

    def method_missing(name, *args)
      @data[name]
    end

    def respond_to_missing?(method, *)
      @data.key?(method)
    end
  end

  def expand_template(template_name, data = {})
    Template.new(template_name, data).__expand
  end
end

RSpec.configure do |config|
  config.include ErbTemplating
end
