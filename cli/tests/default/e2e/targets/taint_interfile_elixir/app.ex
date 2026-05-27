defmodule App do
  def run(), do: sink(Helpers.pass_through(Source.get_input()))
  def sink(value), do: value
end
