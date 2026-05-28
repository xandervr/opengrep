import { CreateChildSource } from "./create_child_source";

class CreateChildApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const parent = {};
parent.bind("source").to(CreateChildSource);
const child = parent.createChild();

new CreateChildApp(child.get("source")).run();
