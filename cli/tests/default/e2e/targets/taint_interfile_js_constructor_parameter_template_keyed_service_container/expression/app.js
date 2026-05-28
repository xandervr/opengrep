import { ExpressionTemplateSource } from "./expression_template_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const SOURCE_SUFFIX = "rce";
const services = {
  [`sou${SOURCE_SUFFIX}`]: new ExpressionTemplateSource(),
};

new App(services[`sou${SOURCE_SUFFIX}`]).run();
