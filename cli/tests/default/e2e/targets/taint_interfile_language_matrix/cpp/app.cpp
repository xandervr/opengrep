void sink(char *);
char *get_input();
char *pass_through(char *);
int main() { sink(pass_through(get_input())); }
