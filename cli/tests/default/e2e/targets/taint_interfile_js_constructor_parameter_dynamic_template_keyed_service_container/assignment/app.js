import { DynamicTemplateAssignmentSource } from "./assignment_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const sourceSuffix = selectServiceSuffix();
const services = {};
services[`sou${sourceSuffix}`] = new DynamicTemplateAssignmentSource();

new App(services[`sou${sourceSuffix}`]).run();
