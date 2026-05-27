export class Base {
  constructor() {
    this.value = source();
  }

  getInput() {
    return this.value;
  }
}

export class Child extends Base {}
