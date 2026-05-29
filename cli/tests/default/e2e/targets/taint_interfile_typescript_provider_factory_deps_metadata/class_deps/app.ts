import { ClassDepAlias, ClassDepSource, ClassDepToken } from "./source";

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function Injectable(): ClassDecorator {
  return () => {};
}

@Module({
  providers: [
    { provide: ClassDepToken, useClass: ClassDepSource },
    {
      provide: ClassDepAlias,
      useFactory: (source) => source,
      deps: [ClassDepToken],
    },
  ],
})
class ClassDepsModule {}

@Injectable()
class ClassDepsApp {
  constructor(source: ClassDepAlias) {
    sink(source.getInput());
  }
}

new ClassDepsApp();
