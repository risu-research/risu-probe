# frozen_string_literal: true

# Execute the ACTUAL pinned upstream Hitch::MCP::ResultNormalizer, not a copy.
# This is a source-level original Ruby model execution. Python later conveys
# the unchanged normalized result over a genuine MCP SDK stdio test wrapper.
require "json"

source_root = File.expand_path(ARGV.fetch(0))
out_path = File.expand_path(ARGV.fetch(1))
base = File.join(source_root, "app", "models", "hitch", "mcp")
require File.join(base, "internal", "json_values.rb")
require File.join(base, "result.rb")
require File.join(base, "internal", "result_normalizer.rb")

schema = {
  "type" => "object",
  "properties" => {"value" => {"type" => "string"}},
  "required" => ["value"],
  "additionalProperties" => false
}

value = {"value" => "RISU-PUBLIC-SYNTHETIC-STRING"}
r = Hitch::MCP::Result
normalizer = Hitch::MCP::Internal::ResultNormalizer
outcomes = {
  "missing_text" => normalizer.call(
    result: r.structured(value), output_schema: schema, max_bytes: 100_000
  ).to_h,
  "explicit_text" => normalizer.call(
    result: r.structured(value, text: "Author supplied summary"),
    output_schema: schema, max_bytes: 100_000
  ).to_h,
  "text_only" => normalizer.call(
    result: r.text("Normal scalar text"), output_schema: nil, max_bytes: 100_000
  ).to_h
}

raise "non JSON result" unless outcomes.values.all? { |v| v.is_a?(Hash) }
out = {
  "schema" => "risu-b11-hitch60-original-ruby-result-v1",
  "source" => "ACTUAL_PINNED_UPSTREAM_RUBY_RESULT_NORMALIZER",
  "records" => outcomes
}
File.open(out_path, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
  file.write(JSON.pretty_generate(out) + "\n")
end
puts "B11_HITCH60_ACTUAL_UPSTREAM_RUBY_NORMALIZER_EXECUTED"
