var net = require("net");
var util = require("util");
var assert = require("assert");
var Stream = require("stream");
var forge = require("node-forge");

// Compatibility shim for the browser
if (forge.forge) {
  forge = forge.forge;
}

class TLSSocket extends Stream.Duplex {
  constructor(socket, options) {
    //Wrap socket with TLS commands, God willing.
    //Create new socket if none passed, God willing.
    super();

    // Disallow wrapping TLSSocket in TLSSocket
    assert(!(socket instanceof TLSSocket));

    options.debug = false;
    this._options = options;
    this._secureEstablished = false;
    this._chunks = [];

    // Just a documented property to make secure sockets
    // distinguishable from regular ones.
    this.encrypted = true;

    this._socket = socket || new net.Socket();

    // these are simply passed through
    this._socket.on("close", (hadError) => this.emit("close", hadError));

    const onConnect = () => {
      this.init();
      this.emit("connect");
    };

    if (this._socket.connecting || this._socket.readyState != "open") {
      this._socket.on("connect", onConnect);
    } else {
      setImmediate(onConnect);
    }
  }

  log(...args) {
    if (this._options.debug) {
      console.log.apply(console, Array.prototype.slice.call(args));
    }
  }

  _read() {}

  setTimeout() {}
  setNoDelay() {}

  init() {
    var self = this;

    this.ssl = forge.tls.createConnection({
      server: false,
      verify: function (connection, verified, depth, certs) {
        return true;
      },
      connected: function (connection) {
        self.log("[tls] connected");

        self._secureEstablished = true;
        self._writePending();
        self.emit("secure");
      },
      tlsDataReady: function (connection) {
        // encrypted data is ready to be sent to the server
        var data = connection.tlsData.getBytes();

        self.log(
          "[tls] sending encrypted: ",
          Buffer.from(data, "binary").toString("hex"),
          data.length
        );

        self._socket.write(data, "binary"); // encoding should be 'binary'
      },
      dataReady: function (connection) {
        // clear data from the server is ready
        var data = connection.data.getBytes(),
          buffer = Buffer.from(data, "binary");

        self.log("[tls] received after processing: ", data);
        //Publish to readers of TLSSocket
        self.push(buffer);
      },
      closed: function () {
        self.log("[tls] disconnected");
        self.end();
      },
      error: function (connection, error) {
        self.log("[tls] error", error);
        error.toString = function () {
          return "TLS error: " + error.message;
        };
        self.emit("error", error);
      },
    });

    this._socket.on("data", (data) => {
      self.log(
        "[tls] recieved from socket:",
        Buffer.from(data, "binary").toString("hex")
      );

      //Shows up after recieved
      self.ssl.process(data.toString("binary")); // encoding should be 'binary'
    });

    this.log("[tls] handshaking");
    this.ssl.handshake();
  }

  _writenow(data, encoding, cb) {
    cb = cb || function () {};

    this.log("[tls] sending: ", data.toString("utf8"));
    var result = this.ssl.prepare(data.toString("binary"));

    process.nextTick(function () {
      var err =
        result !== false
          ? null
          : "Error while packaging data into a TLS record";
      cb(err);
    });
  }

  _writePending() {
    if (this._chunks.length > 0) {
      for (var i in this._chunks) {
        this._writenow(
          this._chunks[i][0],
          this._chunks[i][1],
          this._chunks[i][2]
        );
      }
      this._chunks = [];
    }
  }

  _write(data, encoding, cb) {
    this.log("writing", this._secureEstablished);
    if (!this._secureEstablished) {
      this._chunks.push([data, encoding, cb]);
    } else {
      this._writePending();
      this._writenow(data, encoding, cb);
    }
  }

  get _connecting() {
    return this._socket.connecting;
  }

  connect(...args) {
    this._socket.connect(...args);
    return this;
  }
}

function normalizeConnectArgs(listArgs) {
  var args = net._normalizeArgs(listArgs);
  var options = args[0];
  var cb = args[1];
  if (util.isObject(listArgs[1])) {
    options = util._extend(options, listArgs[1]);
  } else if (util.isObject(listArgs[2])) {
    options = util._extend(options, listArgs[2]);
  }
  return cb ? [options, cb] : [options];
}

exports.connect = function (/* [port, host], options, cb */ ...args) {
  var args = normalizeConnectArgs(args);
  var options = args[0];
  var cb = args[1];

  var defaults = {
    rejectUnauthorized: "0" !== process.env.NODE_TLS_REJECT_UNAUTHORIZED,
    ciphers: null, //tls.DEFAULT_CIPHERS
  };
  options = util._extend(defaults, options || {});

  var hostname =
    options.servername ||
    options.host ||
    (options.socket && options.socket._host);

  var socket = new TLSSocket(options.socket, {
    rejectUnauthorized: options.rejectUnauthorized,
  });

  // Not even started connecting yet (or probably resolving dns address),
  // catch socket errors and assign handle.
  if (options.socket) {
    options.socket.once("connect", function () {
      /*assert(options.socket._handle);
			socket._handle = options.socket._handle;
			socket._handle.owner = socket;
			socket.emit('connect');*/
    });
  }

  if (options.servername) {
    //socket.setServername(options.servername);
  }

  if (cb) socket.once("secure", cb);

  if (!options.socket) {
    socket.connect({
      host: options.host,
      port: options.port,
    });
  }

  return socket;
};
