/* ORBIT LOG games — shared logic.
 * Works in the browser (window.GamesLogic / window.GamesNet) and under
 * Node (module.exports) so the win detection can be unit-tested.
 * No tracking, no ads, no external images. Game data is peer-to-peer
 * via PeerJS; no game server of ours is involved.
 */
(function () {
  "use strict";

  /* ---------------- win detection ---------------- */

  // Gomoku board: 15x15 array of 0 (empty), 1 (black), 2 (white).
  // Returns true when `player` has 5+ in a row through (x, y).
  function checkGomokuWin(board, x, y, player) {
    if (!board || !board[y] || board[y][x] !== player) return false;
    var dirs = [[1, 0], [0, 1], [1, 1], [1, -1]];
    for (var d = 0; d < dirs.length; d++) {
      var dx = dirs[d][0], dy = dirs[d][1], count = 1;
      var nx = x + dx, ny = y + dy;
      while (board[ny] && board[ny][nx] === player) { count++; nx += dx; ny += dy; }
      nx = x - dx; ny = y - dy;
      while (board[ny] && board[ny][nx] === player) { count++; nx -= dx; ny -= dy; }
      if (count >= 5) return true;
    }
    return false;
  }

  // Tic-tac-toe board: flat array of 9 cells, each "X", "O" or null.
  // Returns "X", "O", or null.
  function checkTicTacToeWin(board) {
    if (!board || board.length !== 9) return null;
    var lines = [
      [0, 1, 2], [3, 4, 5], [6, 7, 8],
      [0, 3, 6], [1, 4, 7], [2, 5, 8],
      [0, 4, 8], [2, 4, 6]
    ];
    for (var i = 0; i < lines.length; i++) {
      var a = lines[i][0], b = lines[i][1], c = lines[i][2];
      if (board[a] && board[a] === board[b] && board[a] === board[c]) return board[a];
    }
    return null;
  }

  var GamesLogic = { checkGomokuWin: checkGomokuWin, checkTicTacToeWin: checkTicTacToeWin };

  /* ---------------- PeerJS room helper (browser only) ---------------- */

  var PEERJS_SRC = "https://cdn.jsdelivr.net/npm/peerjs@1.5.4/dist/peerjs.min.js";
  var peerLoadPromise = null;

  function loadPeerJS() {
    if (typeof window === "undefined") return Promise.reject(new Error("no window"));
    if (window.Peer) return Promise.resolve();
    if (peerLoadPromise) return peerLoadPromise;
    peerLoadPromise = new Promise(function (resolve, reject) {
      var s = document.createElement("script");
      s.src = PEERJS_SRC;
      s.onload = function () { resolve(); };
      s.onerror = function () { peerLoadPromise = null; reject(new Error("peerjs load failed")); };
      document.head.appendChild(s);
    });
    return peerLoadPromise;
  }

  function makeCode() {
    // 6 digits, first digit never 0, so the code is always 6 characters.
    return String(Math.floor(100000 + Math.random() * 900000));
  }

  function roomId(game, code) { return "orbit-" + game + "-" + code; }

  // Room object returned to the game page:
  //   room.send(obj)   — sends JSON to the opponent (queued until connected)
  //   room.close()     — closes the connection and destroys the peer
  //   room.code        — the room code (host only; guest: the code entered)
  // Callbacks (cb): onCode(code), onConnected(), onMessage(data),
  //   onDisconnected(), onError(message). All messages are plain Chinese.
  function makeRoom(game, cb) {
    var room = {
      code: null, peer: null, conn: null, connected: false, queue: [],
      send: function (obj) {
        if (this.conn && this.conn.open) { this.conn.send(obj); }
        else { this.queue.push(obj); }
      },
      close: function () {
        try { if (this.conn) this.conn.close(); } catch (e) {}
        try { if (this.peer) this.peer.destroy(); } catch (e) {}
        this.connected = false;
      }
    };
    function wire(conn) {
      room.conn = conn;
      conn.on("open", function () {
        room.connected = true;
        while (room.queue.length) { conn.send(room.queue.shift()); }
        if (cb.onConnected) cb.onConnected();
      });
      conn.on("data", function (data) { if (cb.onMessage) cb.onMessage(data); });
      conn.on("close", function () {
        room.connected = false;
        if (cb.onDisconnected) cb.onDisconnected();
      });
    }
    function fail(msg) { if (cb.onError) cb.onError(msg); }
    return { room: room, wire: wire, fail: fail };
  }

  function createRoom(game, cb) {
    var ctx = makeRoom(game, cb);
    var room = ctx.room;
    var attempts = 0;
    function attempt() {
      attempts++;
      loadPeerJS().then(function () {
        var code = makeCode();
        room.code = code;
        var peer = new window.Peer(roomId(game, code));
        room.peer = peer;
        peer.on("open", function () { if (cb.onCode) cb.onCode(code); });
        peer.on("connection", function (conn) { ctx.wire(conn); });
        peer.on("error", function (err) {
          if (err && err.type === "unavailable-id" && attempts < 10) {
            try { peer.destroy(); } catch (e) {}
            attempt(); // this code is taken — regenerate and retry
          } else {
            ctx.fail("联机出错，请刷新页面重试。");
          }
        });
      }).catch(function () {
        ctx.fail("联机组件加载失败，请检查网络后刷新页面重试。");
      });
    }
    attempt();
    return room;
  }

  function joinRoom(game, code, cb) {
    var ctx = makeRoom(game, cb);
    var room = ctx.room;
    room.code = code;
    loadPeerJS().then(function () {
      var peer = new window.Peer();
      room.peer = peer;
      peer.on("open", function () {
        var conn = peer.connect(roomId(game, code), { reliable: true });
        ctx.wire(conn);
      });
      peer.on("error", function (err) {
        if (err && err.type === "peer-unavailable") {
          ctx.fail("找不到这个房间码，请检查号码是否正确，或让房主确认房间还在。");
        } else {
          ctx.fail("联机出错，请刷新页面重试。");
        }
      });
    }).catch(function () {
      ctx.fail("联机组件加载失败，请检查网络后刷新页面重试。");
    });
    return room;
  }

  var GamesNet = {
    makeCode: makeCode,
    roomId: roomId,
    createRoom: createRoom,
    joinRoom: joinRoom
  };

  if (typeof window !== "undefined") {
    window.GamesLogic = GamesLogic;
    window.GamesNet = GamesNet;
  }
  if (typeof module !== "undefined" && module.exports) {
    module.exports = GamesLogic;
  }
})();
