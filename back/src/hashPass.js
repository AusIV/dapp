import crypto from 'crypto';

/*
 * This module deals with hashing, storing, and checking the user's password.
 */

export class PasswordManagement {
  constructor(localStorage) {
    this.localStorage = localStorage;
  }
  hashPass(password) {
    // Hash the password using pbkdf2 and a 64 bit hash. pbkdf2 makes deriving
    // the hash more expensive. We're using 100,000 rounds to make it pretty
    // slow, but it might be too much for mobile devices (it locks up my
    // OnePlus two for a couple of seconds). It's a careful balance between an
    // acceptable user experience and making sure people with GPUs can just
    // blow through trillions of password combinations quickly.
    var salt = crypto.randomBytes(8);
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(password, salt, 100000, 16, 'sha256', (err, pbkdf2Pass) => {
        if(err) { reject(err) }
        // Return hex representing the hash and the salt. We'll need both to
        // confirm the password later.
        resolve({hash: pbkdf2Pass.toString("hex"), salt: salt.toString("hex")});
      });
    });
  }
  checkPass(password, hash, salt) {
    return new Promise((resolve, reject) => {
      // Hash the password with the same salt as above, as well as the same
      // pbkdf2 parameters.
      //
      // Note that we're using the async version of pbkdf2, which should keep
      // the UI from locking up while it executes, but on my device it still
      // seems to lock up. I'm not sure the browserify version is truly asynchronous.
      crypto.pbkdf2(password, new Buffer(salt, "hex"), 100000, 16, 'sha256', (err, pbkdf2Pass) => {
        if(err) { reject(err) }
        resolve(pbkdf2Pass.equals(new Buffer(hash, "hex")));
      });
    })
  }
  storePass(password, account) {
    // Hashes the password, then stores in localStorage based on the user's
    // ethereum account. In theory we could support multiple Ethereum accounts
    // for a single user this way.
    return this.hashPass(password).then((result) => {
      this.localStorage.setItem(`${account}:password`, JSON.stringify(result));
    })
  }
  checkAccountPass(password, account) {
    // Given an Ethereum account, look up the stored password hash and verify
    // that the provided password hashes to the same value with the given salt.
    var pdata = JSON.parse(this.localStorage.getItem(`${account}:password`));
    if(pdata) {
      return this.checkPass(password, pdata.hash, pdata.salt);
    } else {
      return Promise.resolve(false);
    }
  }
  hasAccountPass(account) {
    // Indicate whether this account has a stored password.
    return !!this.localStorage.getItem(`${account}:password`);
  }
}
