import { DelayBothSource } from "./source";

function registry(_providers: unknown[]): ClassDecorator {
  return () => {};
}

function inject(_key: unknown): ParameterDecorator {
  return () => {};
}

function delay(_callback: () => unknown): unknown {
  return _callback;
}

class DelayBothToken {}

@registry([
  { token: delay(() => DelayBothToken), useValue: new DelayBothSource() },
])
class DelayBothBindings {}

class DelayBothApp {
  constructor(@inject(delay(() => DelayBothToken)) source) {
    sink(source.getInput());
  }
}

new DelayBothBindings();
new DelayBothApp();
