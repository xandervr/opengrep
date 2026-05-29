import { CreateScopeSource } from "./create_scope_source";

class CreateScopeApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const parent = {};
parent.register({
  source: asClass(CreateScopeSource),
});
const scope = parent.createScope();

new CreateScopeApp(scope.resolve("source")).run();
