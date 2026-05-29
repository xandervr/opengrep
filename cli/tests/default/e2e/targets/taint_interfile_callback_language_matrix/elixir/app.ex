defmodule App do
  def run(), do: sink(Higher.apply_callback(fn value -> value end))
end
