import { ResolveAsyncSource } from "./resolve_async_source";

class ResolveAsyncApp {
  constructor(source) {
    this.source = source;
  }

  run() {
    sink(this.source.getInput());
  }
}

const container = {};
container.provide("source").useFactory(async () => {
  return new ResolveAsyncSource();
});

async function main() {
  const helper = await container.resolveAsync("source");
  new ResolveAsyncApp(helper).run();
}

main();
