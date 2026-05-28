export class ForwardRefToken {
  getInput(): string {
    return "";
  }
}

export class ForwardRefTokenImpl {
  getInput(): string {
    return source();
  }
}
