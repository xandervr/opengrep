import { VariableChainSource } from "./variable_chain_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const services = new Map().set("source", new VariableChainSource());

new App(services.get("source")).run();
