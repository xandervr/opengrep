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
  nested: {},
};
const nested = services.nested;
nested.source = new Source();

new App(services.nested.source).run();
