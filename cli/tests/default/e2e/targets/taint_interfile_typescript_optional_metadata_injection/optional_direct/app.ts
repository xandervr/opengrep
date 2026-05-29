import { OptionalDirectSource } from "./source";

function Optional(): ParameterDecorator {
  return () => {};
}

class OptionalDirectApp {
  constructor(@Optional() source: OptionalDirectSource) {
    sink(source.getInput());
  }
}

new OptionalDirectApp();
