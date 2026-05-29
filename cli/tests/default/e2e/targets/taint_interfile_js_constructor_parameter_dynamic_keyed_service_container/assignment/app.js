import { DynamicAssignmentSource } from "./assignment_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const sourceToken = selectServiceKey();
const services = {};
services[sourceToken] = new DynamicAssignmentSource();

new App(services[sourceToken]).run();
