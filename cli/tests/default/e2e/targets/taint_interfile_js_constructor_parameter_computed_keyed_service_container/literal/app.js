import { ComputedLiteralSource } from "./literal_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const SOURCE_PREFIX = "sou";
const SOURCE_KEY = SOURCE_PREFIX + "rce";

const services = {
  [SOURCE_KEY]: new ComputedLiteralSource(),
};

new App(services[SOURCE_KEY]).run();
