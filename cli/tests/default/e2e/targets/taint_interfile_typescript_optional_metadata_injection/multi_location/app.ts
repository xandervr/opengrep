import { MultiLocationSource } from "./source";

function Host(): ParameterDecorator {
  return () => {};
}

function SkipSelf(): ParameterDecorator {
  return () => {};
}

class MultiLocationApp {
  constructor(@Host() @SkipSelf() source: MultiLocationSource) {
    sink(source.getInput());
  }
}

new MultiLocationApp();
