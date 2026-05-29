module 0xcafe::Interfile {
  public fun run() {
    aptos_sink(aptos_pass_through(aptos_get_input()));
  }
}
