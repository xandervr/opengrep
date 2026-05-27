defmodule App do
  def run(), do: Higher.apply_callback(fn value -> sink(value) end)
end
