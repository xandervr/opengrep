import { ComputedAssignmentSource } from "./assignment_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const SOURCE_KEY = "sou" + "rce";
const services = {};
services[SOURCE_KEY] = new ComputedAssignmentSource();

new App(services[SOURCE_KEY]).run();
