#include <errno.h>
#include <libkrun.h>
#include <stdio.h>

int main(void) {

  int err;
  int ctx_id;

  err = krun_set_log_level(1);
  if (err) {
    errno = -err;
    perror("Error configuring log level");
    return -1;
  }

  ctx_id = krun_create_ctx();
  if (ctx_id < 0) {
    errno = -ctx_id;
    perror("Error creating configuration context");
    return -1;
  }

  // set the path for the enclave image file
  if (err = krun_add_eif_file(ctx_id, "~/image.eif")) {
    errno = -err;
    perror("Error setting the enclave's image file");
    return -1;
  }

  // configure the enclave resources
  if (err = krun_set_enclave_config(ctx_id, 1, 2048, 4)) {
    errno = -err;
    perror("Error setting the enclave's resources");
    return -1;
  }

  // Start and enter the enclave. Unless there is some error while creating the
  // enclave, this
  //  function never returns.
  if (err = krun_start_enter(ctx_id)) {
    errno = -err;
    perror("Error creating the enclave");
    return -1;
  }

  return 0;
}
