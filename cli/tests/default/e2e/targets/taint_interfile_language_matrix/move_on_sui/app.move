module 0xcafe::Interfile {
  public fun run() {
    sui_sink(sui_pass_through(sui_get_input()));
  }
}
