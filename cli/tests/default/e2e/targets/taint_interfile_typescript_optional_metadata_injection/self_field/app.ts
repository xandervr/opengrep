import { SelfFieldSource } from "./source";

function Self(): ParameterDecorator {
  return () => {};
}

class SelfFieldApp {
  private source;

  constructor(@Self() source: SelfFieldSource) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

new SelfFieldApp().run();
