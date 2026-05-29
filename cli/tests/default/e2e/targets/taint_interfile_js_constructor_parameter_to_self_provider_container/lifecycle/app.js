import { ToSelfLifecycleSource } from "./source";

class ToSelfLifecycleApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.bind(ToSelfLifecycleSource).toSelf().inSingletonScope();

new ToSelfLifecycleApp(container.get(ToSelfLifecycleSource)).run();
