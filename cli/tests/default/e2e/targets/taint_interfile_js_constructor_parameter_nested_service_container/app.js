import { Source } from "./source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const services = {
  inputs: {
    source: new Source(),
  },
};

new App(services.inputs.source).run();
