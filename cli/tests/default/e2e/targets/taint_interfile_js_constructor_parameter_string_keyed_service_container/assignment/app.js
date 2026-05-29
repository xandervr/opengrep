import { AssignmentSource } from "./assignment_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const services = {};
services["source"] = new AssignmentSource();

new App(services["source"]).run();
