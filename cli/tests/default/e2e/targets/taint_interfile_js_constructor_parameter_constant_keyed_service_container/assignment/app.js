import { ConstantAssignmentSource } from "./assignment_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const SOURCE_KEY = "source";
const services = {};
services[SOURCE_KEY] = new ConstantAssignmentSource();

new App(services[SOURCE_KEY]).run();
