import { LiteralSource } from "./literal_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const services = {
  ["source"]: new LiteralSource(),
};

new App(services["source"]).run();
