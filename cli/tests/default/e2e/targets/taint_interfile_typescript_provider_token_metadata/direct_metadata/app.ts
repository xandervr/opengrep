import { DirectToken, DirectTokenImpl } from "./source";

function Injectable(): ClassDecorator {
  return () => {};
}

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

@Module({
  providers: [{ provide: DirectToken, useClass: DirectTokenImpl }],
})
class DirectTokenModule {}

@Injectable()
class DirectTokenApp {
  constructor(source: DirectToken) {
    sink(source.getInput());
  }
}

new DirectTokenApp();
