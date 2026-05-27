defmodule Higher do
  def apply_callback(callback), do: callback.(Source.get_input())
end
