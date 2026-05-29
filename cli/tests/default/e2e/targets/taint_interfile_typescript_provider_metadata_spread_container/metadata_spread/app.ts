import { MetadataSpreadSource } from "./source";

function bootstrapApplication(_target: unknown, _metadata: unknown): void {}

function Inject(_key: string): ParameterDecorator {
  return () => {};
}

const metadataProviders = [
  { provide: "source", useFactory: () => new MetadataSpreadSource() },
];

const metadata = {
  providers: [...metadataProviders],
};

class MetadataSpreadApp {
  constructor(@Inject("source") source) {
    sink(source.getInput());
  }
}

bootstrapApplication(MetadataSpreadApp, metadata);

new MetadataSpreadApp();
