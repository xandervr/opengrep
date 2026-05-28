import { BootstrapConstantSource } from "./source";

function bootstrapApplication(_target: unknown, _metadata: unknown): void {}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

const bootstrapProviders = [
  { provide: "source", useValue: new BootstrapConstantSource() },
];

class BootstrapConstantApp {
  constructor(@Inject("source") source) {
    sink(source.getInput());
  }
}

bootstrapApplication(BootstrapConstantApp, { providers: bootstrapProviders });

new BootstrapConstantApp();
