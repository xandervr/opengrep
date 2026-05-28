import { NamedEnvironmentSource } from "./source";

function bootstrapApplication(_target: unknown, _metadata: unknown): void {}

function makeEnvironmentProviders(_providers: unknown[]): unknown {
  return _providers;
}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

const environmentProviders = makeEnvironmentProviders([
  { provide: "source", useFactory: () => new NamedEnvironmentSource() },
]);

class NamedEnvironmentApp {
  constructor(@Inject("source") source) {
    sink(source.getInput());
  }
}

bootstrapApplication(NamedEnvironmentApp, {
  providers: [environmentProviders],
});

new NamedEnvironmentApp();
