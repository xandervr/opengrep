import { ForwardRefToken, ForwardRefTokenImpl } from "./source";

function Injectable(): ClassDecorator {
  return () => {};
}

function Module(_metadata: unknown): ClassDecorator {
  return () => {};
}

function forwardRef(_factory: unknown): unknown {
  return {};
}

@Module({
  providers: [{ provide: forwardRef(() => ForwardRefToken), useClass: ForwardRefTokenImpl }],
})
class TokenForwardRefModule {}

@Injectable()
class TokenForwardRefApp {
  constructor(source: ForwardRefToken) {
    sink(source.getInput());
  }
}

new TokenForwardRefApp();
