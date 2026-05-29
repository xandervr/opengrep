import { Source } from "./source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const base = {
  source: new Source(),
};

const services = {
  ...base,
};

new App(services.source).run();
