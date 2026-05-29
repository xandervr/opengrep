import { LiteralTemplateSource } from "./literal_template_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const services = {
  [`source`]: new LiteralTemplateSource(),
};

new App(services[`source`]).run();
