import { ConstantLiteralSource } from "./literal_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const SOURCE_KEY = "source";

const services = {
  [SOURCE_KEY]: new ConstantLiteralSource(),
};

new App(services[SOURCE_KEY]).run();
