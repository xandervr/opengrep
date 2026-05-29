import { AliasSource } from "./alias_source";

class App {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

function createServices() {
  return {
    source: new AliasSource(),
  };
}

const makeServices = createServices;
const { source: appSource } = makeServices();
new App(appSource).run();
