import { CreateChildContainerSource } from "./create_child_container_source";

class CreateChildContainerApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const parent = {};
const child = parent.createChildContainer();
parent.provide("source").useClass(CreateChildContainerSource);

new CreateChildContainerApp(child.resolve("source")).run();
