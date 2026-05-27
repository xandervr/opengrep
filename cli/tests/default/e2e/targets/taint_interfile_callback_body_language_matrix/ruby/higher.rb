require_relative "source"

def apply_callback(callback)
  callback.call(get_input)
end
