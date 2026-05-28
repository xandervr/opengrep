import { RegisterAliasToSource } from "./register_alias_to_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.register("source").asClass(RegisterAliasToSource);
container.register("alias").aliasTo("source");

new App(container.lookup("alias")).run();
