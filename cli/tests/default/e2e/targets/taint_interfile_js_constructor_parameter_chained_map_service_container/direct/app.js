import { DirectChainSource } from "./direct_chain_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

new App(
  new Map().set("source", new DirectChainSource()).get("source")
).run();
